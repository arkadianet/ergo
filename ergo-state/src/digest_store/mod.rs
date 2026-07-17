//! Mode 5 digest-verifier persistence backend — sibling type to
//! [`crate::store::StateStore`].
//!
//! Mode 5 retains an authenticated *digest* of the UTXO state instead
//! of the full AVL+ box arena. The apply seam consumes ADProofs
//! sections (see `crate::digest_apply`) and advances a 33-byte root
//! digest; this store persists that digest, the chain pointers, and
//! a per-height history ledger that drives rollback. No box bytes
//! are written — Mode 5 cannot answer per-input box lookups, and the
//! API-layer gates in `ergo-api` already 503 the affected routes.
//!
//! Atomic-commit invariant: every successful `apply_block_digest`
//! writes
//! `(DIGEST_HISTORY[prev_height], CHAIN_STATE_HISTORY[prev_height],
//! STATE_META["root_digest"], CHAIN_STATE_META["chain_state"],
//! CHAIN_INDEX[new_height], voted_params row if epoch boundary)`
//! inside one redb `write_txn`. A crash mid-apply rolls the whole
//! transition back; no half-applied state survives. Rollback is the
//! same shape in reverse: read the per-height history rows, restore
//! `(root_digest, chain_state)`, truncate every height-indexed table
//! (`DIGEST_HISTORY`, `CHAIN_STATE_HISTORY`, `CHAIN_INDEX`,
//! `VOTED_PARAMS`) above the target.
//!
//! Schema:
//! - `DIGEST_HISTORY[height: u64] -> [u8; 33]` — root digest that was
//!   current AT that height. The rollback substrate, analogous to
//!   the role `LDBVersionedStore` plays in Scala's `DigestState`.
//! - `CHAIN_STATE_HISTORY[height: u64] -> ChainStateMeta` — full
//!   chain-state snapshot at that height, so rollback restores
//!   `best_header_*`, `best_full_block_*`, `header_availability`
//!   atomically with the digest.
//! - `STATE_META["root_digest"] -> [u8; 33]` — current root digest.
//!   Reuses the existing `STATE_META` table with a key distinct from
//!   Mode 1's `"root"` so a misopened store cannot confuse the two.
//! - `CHAIN_STATE_META`, `CHAIN_INDEX`, `VOTED_PARAMS` — shared with
//!   the UTXO backend (same schema).
//!
//! Retention: both history ledgers retain a row for every applied
//! height — there is no bounded-version prune. Mode 1 prunes its
//! `undo_log` below `height - ROLLBACK_WINDOW` on each forward apply;
//! the digest ledgers do not, so the deepest reachable rollback is
//! genesis. A bounded-retention floor (and the matching
//! rollback-below-floor guard) is a separate concern from this
//! schema + atomic-commit layer.
//!
//! Verify/persist boundary: this module PERSISTS digests; it does
//! not VERIFY them. The binding `root_digest == header.state_root`
//! is established by the verifier layer (`crate::digest_apply`'s
//! `DigestProofVerifier::apply_block_in_memory`, which cross-checks
//! the AVL+-computed root against `header.state_root`), and the
//! orchestrator passes only an already-verified root to
//! `apply_block_digest`. The store therefore enforces only
//! self-consistency invariants it can check from its own tables
//! (height monotonicity, dense history/index, non-empty digest at
//! applied heights, voted-params key placement). The store embeds the
//! shared `header_store::HeaderSectionTables`, so it persists headers
//! and block sections and serves the read-side `StateBackend` traits
//! (`ChainStateRead`, `HeaderSectionStore`). What remains deferred to
//! a later layer is the apply-bridge that anchors the persisted digest
//! to a header's `state_root`: that needs the ADProofs section, the
//! boxChanges derivation, and a real-corpus oracle, none of which this
//! read/persist layer owns.
//!
//! The seam is `pub(crate)` and the module is `#![allow(dead_code)]`:
//! no in-crate caller reaches it yet. The boot dispatch and the
//! shared `StateBackend` trait that consume it live in higher
//! layers; this module persists the schema and the atomic-commit
//! invariant on its own. Deferred to those layers (each needs state
//! this schema-only sibling does not own): header-anchored digest
//! validation, intermediate voted-params epoch-row continuity (the
//! section/extension reconcile Mode 1 runs in `reconcile_voted_params`),
//! bounded history retention, and reorg-abort rebuild-from-committed.
#![allow(dead_code)]

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use ergo_validation::{ActiveProtocolParameters, ErgoValidationSettings};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::active_params;
use crate::chain::{ChainStateMeta, HeaderMeta};
use crate::store::StateError;

/// Per-height ledger of the root digest. Key = the height at which
/// that digest was *current*; rollback to height `h` reads
/// `DIGEST_HISTORY[h]` and writes it back to
/// `STATE_META["root_digest"]`.
pub(crate) const DIGEST_HISTORY: TableDefinition<u64, &[u8]> =
    TableDefinition::new("digest_history");

/// Per-height ledger of the full chain-state snapshot. Pairs with
/// `DIGEST_HISTORY` so rollback restores `(root_digest,
/// best_header_*, best_full_block_*, header_availability)`
/// atomically.
pub(crate) const CHAIN_STATE_HISTORY: TableDefinition<u64, &[u8]> =
    TableDefinition::new("chain_state_history");

/// Key in shared `STATE_META` for the current root digest. Distinct
/// from Mode 1's `"root"` so a misopened store cannot confuse the
/// two.
const ROOT_DIGEST_KEY: &str = "root_digest";

/// Key in shared `CHAIN_STATE_META` for the current chain state.
/// Same key the UTXO backend uses — only one is live per data dir,
/// and the `data_dir_state_type` stamp prevents misopening.
const CHAIN_STATE_KEY: &str = "chain_state";

/// `data_dir_state_type` sentinel for the digest-verifier backend.
/// Distinct from the UTXO backend's `"utxo"` AND from the
/// headers-only `StateStore` configuration's `"digest"`: those two
/// share the `StateStore` on-disk schema (an AVL+ arena), while
/// `DigestStateStore` has its own incompatible schema (digest +
/// chain-state history ledgers, no arena). A dir written by one
/// backend can never be safely reopened by the other, so each owns
/// a distinct sentinel and a mismatch is a hard `StateTypeMismatch`.
const DIGEST_VERIFIER_STATE_TYPE: &str = "digest-verifier";

/// All-zeros 33-byte sentinel used as the synthetic genesis seed in
/// this module's unit tests. It is NOT the AVL+ digest of an empty
/// tree (that is the non-zero `4ec61f...0900`) and it is NOT a real
/// network's genesis digest (mainnet's is `a5df...02`). A fresh Mode 5
/// store seeds whatever genesis digest the network supplies through
/// `open`; the synth tests pass this sentinel so their apply/rollback
/// invariants stay self-consistent against a fixed, recognizable
/// height-0 root.
#[cfg(test)]
pub(crate) const EMPTY_AVL_DIGEST: [u8; 33] = [0u8; 33];

/// Mode 5 persistence handle. Holds the redb database and an
/// in-memory mirror of the persisted `(root_digest, chain_state)`
/// pair. Mutated only through `apply_block_digest` and
/// `rollback_to`; both commit atomically. `voting_settings` carries
/// the network's voting-epoch length (used to enforce that a
/// co-committed voted-params row lands only at a real epoch boundary,
/// mirroring the Mode 1 `StateStore` guard) plus the soft-fork
/// thresholds block validation reads.
#[derive(Debug)]
pub struct DigestStateStore {
    db: Arc<Database>,
    root_digest: [u8; 33],
    chain_state: ChainStateMeta,
    /// Network voting parameters (`voting_length` + soft-fork
    /// thresholds). The epoch-boundary guard reads `voting_length`;
    /// block validation reads the soft-fork thresholds. Holds the whole
    /// `VotingParams` so both consumers share one source, mirroring
    /// `StateStore`.
    voting_settings: ergo_chain_spec::VotingParams,
    /// Shared header/section table component — same redb file, same
    /// `Arc<Database>`. Serves the read-side `HeaderSectionStore` trait.
    headers: crate::header_store::HeaderSectionTables,
    /// Active protocol parameters at the current tip: the latest
    /// `voted_params` row at or below the committed height. Computed at
    /// open and refreshed by `refresh_cached_params_post_commit` after
    /// every apply/rollback so it always tracks the committed tip.
    active_params: ActiveProtocolParameters,
    /// Cumulative validation settings at the current tip — the fold of
    /// every `voted_params` row's `activated_update` up to the tip.
    /// Refreshed alongside `active_params` on every commit.
    validation_settings: ErgoValidationSettings,
    /// Session-scoped invalidity: cleared on every restart. Persistent
    /// invalidity is reserved for cryptographically definitive failures
    /// the digest backend does not yet produce.
    session_invalids: HashSet<[u8; 32]>,
    /// The network's height-0 AVL+ root digest (post the genesis boxes),
    /// supplied at `open` from `GenesisParams::state_digest`. This is the
    /// digest a fresh store seeds, the value `read_consistent_state`
    /// expects at height 0, and the root `rollback_to(0)` must restore.
    /// Mainnet's is `a5df...02`; it is never the all-zero or empty-tree
    /// digest.
    genesis_state_digest: [u8; 33],
}

impl DigestStateStore {
    /// Open or initialize a Mode 5 store at `path`. Verifies the
    /// `data_dir_state_type` stamp is `"digest-verifier"` (or stamps
    /// it on a fresh dir); refuses any dir previously initialized for
    /// the UTXO backend or the headers-only `StateStore` (`"digest"`).
    ///
    /// Persistence consistency is enforced by `read_consistent_state`:
    /// `CHAIN_STATE_META["chain_state"]` is the authoritative anchor,
    /// and `root_digest`, the `CHAIN_INDEX` tip, and the two history
    /// ledgers are cross-checked against it. A torn write — any
    /// missing or mismatched row — surfaces as `DbCorruption` at open
    /// rather than booting a node that fails later at a reorg.
    ///
    /// `voting_settings` supplies the network's voting-epoch length so
    /// `apply_block_digest` can reject a voted-params row at a
    /// non-epoch-start height, matching the Mode 1 guard.
    ///
    /// On a fresh dir, seeds the `voted_params` height-0 row from
    /// `launch_params` so the validator's epoch-boundary logic has
    /// a baseline to compare against (mirrors
    /// `StateStore::reconcile_voted_params` open-time behavior).
    ///
    /// `genesis_state_digest` is the network's height-0 AVL+ root (from
    /// `GenesisParams::state_digest`). A fresh dir boots with this digest
    /// as its root — Mode 5 verifies block 1 against the real genesis
    /// state, not an empty tree — and `read_consistent_state` /
    /// `rollback_to` use it as the height-0 reference value.
    pub fn open(
        path: &Path,
        launch_params: ActiveProtocolParameters,
        voting_settings: ergo_chain_spec::VotingParams,
        genesis_state_digest: [u8; 33],
    ) -> Result<Self, StateError> {
        let db = Arc::new(crate::redb_util::open_with_repair_logging(
            path,
            "digest_state_store",
        )?);

        // Resolve the state-type sentinel READ-ONLY first: this
        // fail-fasts on a wrong existing sentinel (clean
        // StateTypeMismatch) but does NOT write. The sentinel is
        // only stamped at the end, after the digest-shape validation
        // below passes — so a failed mis-open (e.g. a headers-only
        // StateStore dir opened as Mode 5) never poisons the dir's
        // on-disk classification.
        let resolution = crate::store::check_state_type_inner(&db, DIGEST_VERIFIER_STATE_TYPE)?;

        let loaded = read_consistent_state(&db, &genesis_state_digest)?;

        // Genesis voted-params baseline. On a FRESH dir, seed the
        // height-0 row from `launch_params` (mirrors
        // `StateStore::reconcile_voted_params`). On a dir with
        // committed state, the row must already exist — a missing
        // genesis row would let `read_latest_at` silently fall back
        // to the wrong epoch's parameters, so it is loud corruption,
        // not a re-seed. Full historical-ledger reconciliation
        // against the applied tip needs block-section storage this
        // sibling does not yet own and is handled where sections live.
        if loaded.fresh {
            // Cross-network mis-open guard for a NEVER-APPLIED dir. A
            // fresh store persists no genesis digest (the root lives in
            // memory until the first apply writes DIGEST_HISTORY[0]), so
            // the committed-store guard `require_genesis_history_matches`
            // has nothing to compare against here. The one row a prior
            // fresh open DID persist is the genesis `VOTED_PARAMS[0]`
            // launch baseline — so if it is already present it must
            // equal the launch params for THIS network, else this dir
            // was initialized for a different network (e.g. a mainnet
            // dir reopened as testnet before any block applied) and
            // reusing the stale row would run validation against the
            // wrong protocol baseline.
            require_genesis_voted_params_match_or_seed(&db, &launch_params)?;
        } else {
            require_genesis_voted_params_present(&db)?;
        }
        // Reject orphan / off-boundary voted-params rows. (A missing
        // intermediate boundary row is a separate, deferred check —
        // it needs the section-extension reconcile mechanism.)
        validate_voted_params_keys(
            &db,
            loaded.chain_state.best_full_block_height,
            voting_settings.voting_length,
        )?;

        // Everything validated — NOW it is safe to persist the
        // sentinel on a previously-unstamped dir.
        if let crate::store::StateTypeResolution::NeedsStamp(value) = &resolution {
            crate::store::stamp_state_type_inner(&db, value)?;
        }

        // Cached read-state at the committed tip. Both fold over the
        // persisted `voted_params` rows, so they are correct for any
        // tip, not only genesis; `refresh_cached_params_post_commit`
        // keeps them consistent after every apply/rollback. A genesis
        // tip with only the launch row folds to the launch params and
        // empty settings — the Scala launch baseline.
        let (active_params, validation_settings) = {
            let read = db.begin_read()?;
            let h = loaded.chain_state.best_full_block_height;
            let params = crate::active_params::read_latest_at(&read, h)?
                .unwrap_or_else(|| launch_params.clone());
            let settings = crate::active_params::compute_validation_settings_at(&read, h)?;
            (params, settings)
        };
        let headers = crate::header_store::HeaderSectionTables::new(db.clone());

        // Header-anchor the persisted tip root: for an applied store the
        // stored root must equal the tip header's committed `state_root`.
        // This is the integrity check the genesis-seed change displaced —
        // without it a root mutated to any plausible value (the genesis
        // digest included) would boot clean and only diverge at the next
        // apply. A fresh/genesis tip has no applied block header to anchor
        // against; its root is already pinned to the network genesis digest
        // by `read_consistent_state`.
        if loaded.chain_state.best_full_block_height >= 1 {
            require_root_matches_tip_header(
                &headers,
                &loaded.chain_state.best_full_block_id,
                &loaded.root_digest,
            )?;
        }

        Ok(Self {
            db,
            root_digest: loaded.root_digest,
            chain_state: loaded.chain_state,
            voting_settings,
            headers,
            active_params,
            validation_settings,
            session_invalids: HashSet::new(),
            genesis_state_digest,
        })
    }

    /// A cloned `Arc` handle to the underlying redb `Database`. Mirrors
    /// [`StateStore::db_arc`] so boot-time subsystems (the wallet writer
    /// task) can open their own read transactions against the same file
    /// without a backend-typed branch. The digest db holds no box arena,
    /// so UTXO-dependent wallet reads see an empty set — wallet routes are
    /// subsystem-gated off in Mode 5 regardless.
    pub fn db_arc(&self) -> Arc<Database> {
        self.db.clone()
    }

    /// Current root digest. Returns the network's genesis digest on a
    /// fresh store (no apply yet).
    pub fn root_digest(&self) -> [u8; 33] {
        self.root_digest
    }

    /// Current `best_full_block_height`. 0 on a fresh store.
    pub fn height(&self) -> u32 {
        self.chain_state.best_full_block_height
    }

    /// Read-only handle to the in-memory chain-state mirror. Reflects
    /// the last committed write.
    pub fn chain_state(&self) -> &ChainStateMeta {
        &self.chain_state
    }

    /// Network voting parameters seeded at `open`. Stable for the
    /// store's lifetime — `voting_length` and the soft-fork thresholds
    /// are network constants, not per-epoch state. Block validation
    /// consumes this so epoch-boundary and soft-fork-vote logic use the
    /// right cadence; mirrors `StateStore::voting_settings`.
    pub fn voting_settings(&self) -> &ergo_chain_spec::VotingParams {
        &self.voting_settings
    }

    /// Sparse-aware best-chain height lookup, mirroring
    /// [`StateStore::lookup_header_at_height`]. The digest backend is
    /// always `HeaderAvailability::Dense` (Mode 5 does not NiPoPoW-
    /// bootstrap), so a missing row at or below the header tip is store
    /// corruption rather than an expected sparse gap; the both-arms
    /// handling matches `StateStore` so the `ChainView` semantics are
    /// identical across backends.
    pub fn lookup_header_at_height(
        &self,
        height: u32,
    ) -> Result<crate::chain::HeightLookup, StateError> {
        use crate::backend::HeaderSectionStore;
        use crate::chain::{HeaderAvailability, HeightLookup};
        if let Some(id) = self.get_header_id_at_height(height)? {
            return Ok(HeightLookup::Dense(id));
        }
        if height > self.chain_state.best_header_height {
            return Ok(HeightLookup::AboveTip);
        }
        match self.chain_state.header_availability {
            HeaderAvailability::Dense => {
                tracing::error!(
                    height,
                    best_header_height = self.chain_state.best_header_height,
                    "HEADER_CHAIN_INDEX missing row in Dense mode — digest store corruption",
                );
                Ok(HeightLookup::SparseGap)
            }
            HeaderAvailability::PoPowSparse {
                dense_from_height, ..
            } => {
                if height < dense_from_height {
                    Ok(HeightLookup::SparseGap)
                } else {
                    tracing::error!(
                        height,
                        dense_from_height,
                        best_header_height = self.chain_state.best_header_height,
                        "HEADER_CHAIN_INDEX missing row inside dense range (digest, PoPowSparse)",
                    );
                    Ok(HeightLookup::SparseGap)
                }
            }
        }
    }

    /// Apply a block in digest mode. Atomically commits
    /// `(DIGEST_HISTORY[prev_height], CHAIN_STATE_HISTORY[prev_height],
    /// STATE_META["root_digest"], CHAIN_STATE_META["chain_state"],
    /// CHAIN_INDEX[new_height], voted_params if epoch boundary)`
    /// inside one redb write_txn.
    ///
    /// Pre-flight: `new_chain_state.best_full_block_height` must be
    /// exactly `self.height() + 1` — digest-mode apply has no
    /// skip-or-replay semantics. The caller (Mode 5 orchestrator)
    /// constructs the full `ChainStateMeta` because the score and
    /// availability fields originate at the header / NiPoPoW layer
    /// the orchestrator owns.
    ///
    /// The caller is also responsible for having already run the
    /// in-memory apply (see `crate::digest_apply::DigestProofVerifier`)
    /// and confirmed `new_root_digest == header.state_root`. This
    /// seam commits only — it does not re-verify the proof.
    pub fn apply_block_digest(
        &mut self,
        new_root_digest: [u8; 33],
        new_chain_state: ChainStateMeta,
        voted_params_row: Option<ActiveProtocolParameters>,
    ) -> Result<(), StateError> {
        let new_height = new_chain_state.best_full_block_height;
        let prev_height = self.height();
        if new_height != prev_height + 1 {
            return Err(StateError::ApplyOutOfOrder {
                expected_next: prev_height + 1,
                got: new_height,
            });
        }
        // Internal fork-choice invariants on the caller-supplied
        // chain state (best_header must lead or equal best_full_block;
        // score is never empty). Full validation of best_header_*
        // against persisted header state needs the header tables this
        // sibling does not own; these cheap invariants catch an
        // obviously-nonsense best-header view at the seam.
        if let Err(reason) = chain_state_internal_invariant(&new_chain_state) {
            return Err(StateError::InvalidPrecondition { what: reason });
        }
        // A co-committed voted-params row must land only at a real
        // epoch boundary and must be keyed to this block's height —
        // the same two-part guard Mode 1's `persist_apply` applies.
        // The first check stops a row at a non-epoch-start height;
        // the second stops a row keyed to the wrong epoch (which
        // `compute_validation_settings_at` would later fold into the
        // wrong active parameters) and also prevents clobbering the
        // genesis row (key 0), since `new_height >= 1` here. These
        // are caller-misuse conditions (`voted_params_row` is an
        // argument, not on-disk data), hence `InvalidPrecondition`.
        if let Some(p) = &voted_params_row {
            if !(new_height.is_multiple_of(self.voting_settings.voting_length) && new_height > 0) {
                return Err(StateError::InvalidPrecondition {
                    what: "voted_params_row supplied at non-epoch-start height",
                });
            }
            if p.epoch_start_height != new_height {
                return Err(StateError::InvalidPrecondition {
                    what: "voted_params_row.epoch_start_height != block height",
                });
            }
        }
        let prev_root = self.root_digest;
        let prev_chain_state_bytes = self.chain_state.serialize();
        let new_chain_state_bytes = new_chain_state.serialize();

        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            // 1. Record the digest we're moving AWAY from at its
            //    height — rollback_to(prev_height) restores from
            //    here.
            let mut history = write_txn.open_table(DIGEST_HISTORY)?;
            history.insert(prev_height as u64, &prev_root[..])?;
            drop(history);

            // 2. Record the chain state we're moving AWAY from,
            //    paired with the digest row. Restored together.
            let mut state_history = write_txn.open_table(CHAIN_STATE_HISTORY)?;
            state_history.insert(prev_height as u64, prev_chain_state_bytes.as_slice())?;
            drop(state_history);

            // 3. Advance STATE_META["root_digest"] to the new value.
            let mut meta = write_txn.open_table(crate::store::STATE_META)?;
            meta.insert(ROOT_DIGEST_KEY, &new_root_digest[..])?;
            drop(meta);

            // 4. Advance CHAIN_STATE_META["chain_state"] —
            //    authoritative chain pointers.
            let mut chain_state_table = write_txn.open_table(crate::store::CHAIN_STATE_META)?;
            chain_state_table.insert(CHAIN_STATE_KEY, new_chain_state_bytes.as_slice())?;
            drop(chain_state_table);

            // 5. Advance CHAIN_INDEX with the new best-block pointer.
            let mut chain_index = write_txn.open_table(crate::store::CHAIN_INDEX)?;
            chain_index.insert(new_height as u64, &new_chain_state.best_full_block_id[..])?;
            drop(chain_index);

            // 6. Optional voted-params row at epoch boundaries.
            //    Same write_txn so a crash before commit rolls the
            //    params row back with the digest.
            if let Some(p) = voted_params_row {
                active_params::insert(&write_txn, &p).map_err(|e| {
                    StateError::VotedParamsWriteFailed {
                        op: "digest-mode apply",
                        height: new_height,
                        source: Box::new(e),
                    }
                })?;
            }
        }
        write_txn.commit()?;

        self.root_digest = new_root_digest;
        self.chain_state = new_chain_state;
        self.refresh_cached_params_post_commit();
        Ok(())
    }

    /// Roll back to `target_height`. Reads
    /// `DIGEST_HISTORY[target_height]` and
    /// `CHAIN_STATE_HISTORY[target_height]`, writes them back to
    /// `STATE_META["root_digest"]` and
    /// `CHAIN_STATE_META["chain_state"]`, truncates every height-
    /// indexed table (`DIGEST_HISTORY`, `CHAIN_STATE_HISTORY`,
    /// `CHAIN_INDEX`, `VOTED_PARAMS`) above the target, all inside
    /// one redb write_txn.
    ///
    /// `target_height` must be `<= self.height()` and rows must
    /// exist at the target. Rolling FORWARD via this seam is
    /// meaningless.
    pub fn rollback_to(&mut self, target_height: u32) -> Result<(), StateError> {
        if target_height > self.height() {
            return Err(StateError::RollbackBeyondTip {
                target: target_height,
                tip: self.height(),
            });
        }
        if target_height == self.height() {
            return Ok(());
        }

        // Pre-read both restoration rows in a read txn so we fail
        // before touching the write txn if either is missing.
        let restored_root = read_digest_history_row(&self.db, target_height)?;
        let restored_chain_state = read_chain_state_history_row(&self.db, target_height)?;

        // Validate the restored ROOT digest BEFORE committing it —
        // applied live so a reorg never installs a poisoned root.
        // Rolling back to height 0 MUST restore exactly the network's
        // genesis root (digest_history[0] is the genesis row, and there
        // is no applied tip header at genesis to anchor against). For an
        // applied target `h >= 1` the restored root is instead anchored
        // to the tip header's committed `state_root` below, so a mutated
        // `DIGEST_HISTORY[h]` cannot install a wrong root. Other
        // torn-write cases are caught by the snapshot height/id and
        // chain_index cross-checks below.
        if target_height == 0 && restored_root != self.genesis_state_digest {
            return Err(StateError::DbCorruption {
                table: "digest_history",
                key: "0".into(),
                reason: format!(
                    "rollback to genesis would restore root {} != the network's \
                     genesis digest — digest_history[0] is corrupt",
                    hex::encode(restored_root)
                ),
            });
        }

        // Validate the restored snapshot's payload BEFORE committing
        // it: a `CHAIN_STATE_HISTORY` row that decodes cleanly but
        // carries the wrong height or block id (torn write / external
        // mutation) would otherwise be written straight into
        // `CHAIN_STATE_META`, leaving the store internally
        // inconsistent. The snapshot at key `target_height` must
        // claim exactly that height, and (for an applied target) its
        // `best_full_block_id` must equal `CHAIN_INDEX[target]` — the
        // row that becomes the post-rollback tip.
        if restored_chain_state.best_full_block_height != target_height {
            return Err(StateError::DbCorruption {
                table: "chain_state_history",
                key: format!("{target_height}"),
                reason: format!(
                    "snapshot at key {target_height} claims height {} — body does not \
                     match its key",
                    restored_chain_state.best_full_block_height
                ),
            });
        }
        if let Err(reason) = chain_state_internal_invariant(&restored_chain_state) {
            return Err(StateError::DbCorruption {
                table: "chain_state_history",
                key: format!("{target_height}"),
                reason: reason.into(),
            });
        }
        if target_height >= 1 {
            let tip_id = read_chain_index_id(&self.db, target_height)?;
            if tip_id != restored_chain_state.best_full_block_id {
                return Err(StateError::DbCorruption {
                    table: "chain_state_history",
                    key: format!("{target_height}"),
                    reason: format!(
                        "snapshot best_full_block_id {} disagrees with chain_index[{target_height}] {}",
                        hex::encode(restored_chain_state.best_full_block_id),
                        hex::encode(tip_id),
                    ),
                });
            }
            // Header-anchor the root being restored: the snapshot root must
            // equal the target tip header's committed `state_root`, else a
            // mutated `DIGEST_HISTORY[target]` would install a poisoned root
            // live — the converse of the open-path check, enforced here so a
            // reorg cannot reach what open would have rejected.
            require_root_matches_tip_header(
                &self.headers,
                &restored_chain_state.best_full_block_id,
                &restored_root,
            )?;
        }

        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut meta = write_txn.open_table(crate::store::STATE_META)?;
            meta.insert(ROOT_DIGEST_KEY, &restored_root[..])?;
            drop(meta);

            let mut chain_state_table = write_txn.open_table(crate::store::CHAIN_STATE_META)?;
            let restored_bytes = restored_chain_state.serialize();
            chain_state_table.insert(CHAIN_STATE_KEY, restored_bytes.as_slice())?;
            drop(chain_state_table);

            truncate_above_height(&write_txn, DIGEST_HISTORY, target_height)?;
            truncate_above_height(&write_txn, CHAIN_STATE_HISTORY, target_height)?;
            truncate_above_height(&write_txn, crate::store::CHAIN_INDEX, target_height)?;

            // VOTED_PARAMS rows above target_height roll back too —
            // an epoch-boundary reorg must not leave future epoch
            // parameters in tree.
            active_params::delete_above(&write_txn, target_height).map_err(|e| {
                StateError::VotedParamsWriteFailed {
                    op: "digest-mode rollback prune",
                    height: target_height,
                    source: Box::new(e),
                }
            })?;
        }
        write_txn.commit()?;

        self.root_digest = restored_root;
        self.chain_state = restored_chain_state;
        self.refresh_cached_params_post_commit();
        Ok(())
    }

    /// Refresh the cached active params + validation settings from the
    /// committed tip after a successful apply or rollback. Mirrors the
    /// UTXO backend's fatal posture: the caches govern later block
    /// validation, so a stale cache after a successful commit would
    /// validate against the wrong active set — a consensus divergence.
    /// Every failure mode here (db read error, missing genesis row,
    /// row-decode failure) is a stop-the-world event, so we panic
    /// rather than let the store drift silently from Scala. The genesis
    /// `voted_params` row is seeded at open, so the `None` arm is a
    /// should-never-happen guard, not a normal path.
    fn refresh_cached_params_post_commit(&mut self) {
        let h = self.chain_state.best_full_block_height;
        let read = self.db.begin_read().unwrap_or_else(|e| {
            panic!(
                "[digest-state] FATAL: cache refresh begin_read failed at h={h}: {e}. \
                 Validation cannot continue safely after a successful commit."
            )
        });
        match crate::active_params::read_latest_at(&read, h) {
            Ok(Some(p)) => self.active_params = p,
            Ok(None) => panic!(
                "[digest-state] FATAL: voted_params cache refresh found no row <= h={h} \
                 post-commit. open()'s seed should have written the genesis row — \
                 this is a bug or db corruption."
            ),
            Err(e) => panic!(
                "[digest-state] FATAL: active_params cache refresh failed at h={h}: {e}. \
                 Validation cannot continue safely after a successful commit."
            ),
        }
        match crate::active_params::compute_validation_settings_at(&read, h) {
            Ok(s) => self.validation_settings = s,
            Err(e) => panic!(
                "[digest-state] FATAL: validation_settings cache refresh failed at h={h}: {e}. \
                 Validation cannot continue safely after a successful commit."
            ),
        }
    }

    /// Set the in-memory tip `(root_digest, chain_state)`. Test-only seam
    /// for the Mode 5 executor-replay oracle; see
    /// `crate::test_helpers::DigestStateStore::seed_tip_for_test`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn set_tip_internal_for_test_helpers(
        &mut self,
        root_digest: [u8; 33],
        chain_state: ChainStateMeta,
    ) {
        self.root_digest = root_digest;
        self.chain_state = chain_state;
        // Re-derive the cached params/settings at the new tip height, so a
        // `voted_params` row seeded for the tip's epoch is reflected in
        // `active_params()` / `validation_settings()` (mirrors the
        // post-commit refresh `apply_block_digest` runs).
        self.refresh_cached_params_post_commit();
    }

    /// Insert a `voted_params` row in its own write txn, then refresh the
    /// cached params/settings. Test-only seam for the Mode 5
    /// executor-replay oracle; see
    /// `crate::test_helpers::DigestStateStore::seed_voted_params_row_for_test`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn insert_voted_params_internal_for_test_helpers(
        &mut self,
        params: &ActiveProtocolParameters,
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        active_params::insert(&write_txn, params).map_err(|e| {
            StateError::VotedParamsWriteFailed {
                op: "test-helper voted_params seed",
                height: params.epoch_start_height,
                source: Box::new(e),
            }
        })?;
        write_txn.commit()?;
        self.refresh_cached_params_post_commit();
        Ok(())
    }

    /// Write `HEADER_CHAIN_INDEX[height] = header_id`. Test-only seam for
    /// the Mode 5 executor-replay oracle; see
    /// `crate::test_helpers::DigestStateStore::seed_header_chain_index_for_test`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn set_header_chain_index_internal_for_test_helpers(
        &self,
        height: u32,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut idx = write_txn.open_table(crate::store::HEADER_CHAIN_INDEX)?;
            idx.insert(height as u64, &header_id[..])?;
        }
        write_txn.commit()?;
        Ok(())
    }
}

impl crate::backend::ChainStateRead for DigestStateStore {
    fn height(&self) -> u32 {
        self.chain_state.best_full_block_height
    }
    fn chain_state_meta(&self) -> ChainStateMeta {
        self.chain_state.clone()
    }
    fn active_params(&self) -> &ActiveProtocolParameters {
        &self.active_params
    }
    fn validation_settings(&self) -> &ErgoValidationSettings {
        &self.validation_settings
    }
    fn read_minimal_full_block_height(&self) -> Result<u32, StateError> {
        // The digest backend does not prune (no Mode-3 retention floor),
        // so every full block down to genesis is retained.
        Ok(1)
    }
}

impl crate::backend::HeaderSectionStore for DigestStateStore {
    fn get_header(&self, header_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        self.headers.get_header(header_id)
    }
    fn get_header_meta(&self, header_id: &[u8; 32]) -> Result<Option<HeaderMeta>, StateError> {
        self.headers.get_header_meta(header_id)
    }
    fn get_header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        self.headers.get_header_id_at_height(height)
    }
    fn get_block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        // No persist pipeline to drain — the digest store commits header
        // and section writes synchronously, unlike the UTXO backend's
        // batched async commit, so the read sees committed state directly.
        self.headers.get_block_section(modifier_id)
    }
    fn get_section_height(&self, section_id: &[u8; 32]) -> Result<Option<u32>, StateError> {
        self.headers.get_section_height(section_id)
    }
    fn scan_header_chain_range(
        &self,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<(u32, [u8; 32])>, StateError> {
        self.headers.scan_header_chain_range(lo, hi)
    }
    fn store_header(&self, header_id: &[u8; 32], header_bytes: &[u8]) -> Result<(), StateError> {
        self.headers.store_header(header_id, header_bytes)
    }
    fn store_validated_header(
        &mut self,
        header_id: &[u8; 32],
        header_bytes: &[u8],
        meta: &HeaderMeta,
        new_best: Option<(u32, Vec<u8>)>,
    ) -> Result<(), StateError> {
        // `self.chain_state` IS the persisted `ChainStateMeta`, so unlike
        // the UTXO backend there is no `to_persisted()` projection — pass
        // a clone, mirror it back only after the delegate commits.
        let mut cs_meta = self.chain_state.clone();
        let r = self.headers.store_validated_header(
            header_id,
            header_bytes,
            meta,
            new_best,
            &mut cs_meta,
        );
        if r.is_ok() {
            self.chain_state = cs_meta;
        }
        r
    }
    fn store_block_section_typed(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
        section_type: u8,
    ) -> Result<(), StateError> {
        self.headers
            .store_block_section_typed(modifier_id, section_bytes, section_type)
    }
    fn begin_header_batch(&mut self) {
        self.headers.begin_header_batch()
    }
    fn flush_header_batch(&mut self) -> Result<(), StateError> {
        let cs_after = self.chain_state.clone();
        self.headers.flush_header_batch(&cs_after)
    }
    fn mark_session_invalid(&mut self, header_id: [u8; 32]) {
        self.session_invalids.insert(header_id);
    }
    fn invalidate_validation_branch(
        &mut self,
        header_id: [u8; 32],
    ) -> Result<Vec<[u8; 32]>, StateError> {
        // Digest-mode invalidity is session-scoped by contract (a stale local
        // parent root and a definitively bad block are observationally
        // identical here — see `BlockProcessError::DigestApply`), so there is
        // no durable branch flag to persist. The executor's validation-verdict
        // classifier does not route digest apply failures here; this satisfies
        // the shared trait for the non-incident path. Delegate the insert to
        // `mark_session_invalid` so it stays the single source of truth.
        self.mark_session_invalid(header_id);
        Ok(vec![header_id])
    }
    fn is_invalid(&self, header_id: &[u8; 32]) -> Result<bool, StateError> {
        Ok(self.session_invalids.contains(header_id))
    }
    fn reader_handle(&self) -> crate::reader::ChainStoreReader {
        crate::reader::ChainStoreReader::new(self.db.clone())
    }
    fn shutdown_cleanly(&mut self) -> Result<(), StateError> {
        // No persist pipeline to drain.
        Ok(())
    }
}

impl crate::backend::BlockApply for DigestStateStore {
    /// Apply a fully-validated block in digest mode. LINEAR-ONLY: the
    /// block's parent must be the committed tip. The block's ADProofs
    /// section (fetched from the section store, not carried by
    /// `CheckedBlock`) is verified against the parent digest and the
    /// header's `state_root`; the verified root is then committed
    /// atomically via [`Self::apply_block_digest`].
    fn apply_full_block(
        &mut self,
        block: &ergo_validation::block::CheckedBlock,
        voted_params_row: Option<ActiveProtocolParameters>,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
    ) -> Result<(), StateError> {
        // The digest backend stores no box arena, so it cannot drive a
        // wallet scan. Mode 5 gates the wallet routes off, so the
        // executor must never attach a hook here; a `Some` is a wiring
        // bug, surfaced loudly rather than silently dropping updates.
        if wallet_hook.is_some() {
            return Err(StateError::InvalidPrecondition {
                what: "digest backend received a wallet hook; Mode 5 has no box arena to scan",
            });
        }

        let header = block.header().header();

        // Linear-only preflight: reject a non-tip parent BEFORE any
        // proof work. Fork / non-tip-parent apply (sourcing the parent
        // root from DIGEST_HISTORY) is deferred. `apply_block_digest`
        // re-checks height at commit; doing it here avoids verifying a
        // proof we would then refuse to commit.
        let prev_height = self.chain_state.best_full_block_height;
        let new_height = header.height;
        if new_height != prev_height + 1 {
            return Err(StateError::ApplyOutOfOrder {
                expected_next: prev_height + 1,
                got: new_height,
            });
        }
        // Linear-only: the block's parent must BE the committed tip.
        // A non-tip parent is a fork / non-tip-parent block, deferred —
        // and crucially NOT invalid. We reject it here, before the
        // verifier (which is always seeded with OUR tip root) can
        // misclassify a foreign-parent block as session-invalid. At
        // genesis both sides are the all-zero genesis-parent sentinel,
        // so this also admits the height-1 block.
        let parent_id = *header.parent_id.as_bytes();
        if parent_id != self.chain_state.best_full_block_id {
            return Err(StateError::DigestNonLinearParent {
                height: new_height,
                expected: hex::encode(self.chain_state.best_full_block_id),
                got: hex::encode(parent_id),
            });
        }

        // Canonical header id via round-trip serialize — derived
        // identically to the verifier's own section-id gate, so the
        // section we look up is the one the gate re-derives.
        let (_, header_id_modifier) = ergo_ser::header::serialize_header(header)
            .map_err(|e| StateError::Serialization(format!("serialize_header: {e:?}")))?;
        let header_id = *header_id_modifier.as_bytes();
        let header_id_hex = hex::encode(header_id);
        let ad_proofs_id = ergo_ser::modifier_id::compute_section_id(
            ergo_ser::modifier_id::TYPE_AD_PROOFS,
            &header_id,
            header.ad_proofs_root.as_bytes(),
        );

        // Fetch the persisted ADProofs section. Absence is
        // data-availability (the proof has not been downloaded/stored
        // yet), NOT block invalidity — do not mark session-invalid.
        let section_bytes = self
            .headers
            .get_block_section(&ad_proofs_id)?
            .ok_or_else(|| StateError::DigestAdProofsSectionMissing {
                header_id: header_id_hex.clone(),
                ad_proofs_id: hex::encode(ad_proofs_id),
            })?;

        // Parse the section envelope and re-enforce the trailing-byte
        // and inner-header-id checks ingress performs, so a persisted
        // blob can never bypass them. A failure here is corruption of
        // our own stored section, not a consensus rejection of the
        // block.
        let mut reader = ergo_primitives::reader::VlqReader::new(&section_bytes);
        let ad_proofs = ergo_ser::ad_proofs::read_ad_proofs(&mut reader).map_err(|e| {
            StateError::DbCorruption {
                table: "block_sections",
                key: hex::encode(ad_proofs_id),
                reason: format!("ADProofs section failed to parse: {e:?}"),
            }
        })?;
        if !reader.is_empty() {
            return Err(StateError::DbCorruption {
                table: "block_sections",
                key: hex::encode(ad_proofs_id),
                reason: format!(
                    "ADProofs section has {} trailing byte(s) after the proof",
                    reader.remaining()
                ),
            });
        }
        if ad_proofs.header_id.as_bytes() != &header_id {
            return Err(StateError::DbCorruption {
                table: "block_sections",
                key: hex::encode(ad_proofs_id),
                reason: format!(
                    "ADProofs section carries header_id {} but is filed under header {header_id_hex}",
                    hex::encode(ad_proofs.header_id.as_bytes()),
                ),
            });
        }

        // Net box changes — Mode 1's exact builder, shared so the
        // digest verifier and the UTXO tree cannot diverge on the same
        // block's change set.
        let (to_remove, to_insert) =
            crate::store::StateStore::build_utxo_changes_checked(block.transactions())?;

        // Data-input lookups, in transaction order (duplicates kept) —
        // the `toLookup` prefix of Scala's `StateChanges.operations`
        // (`toLookup ++ toRemove ++ toAppend`). The ADProofs were
        // generated by replaying these lookups first, so the verifier
        // must consume them first to keep the proof stream aligned.
        let to_lookup: Vec<[u8; 32]> = block
            .transactions()
            .iter()
            .flat_map(|c| {
                c.transaction()
                    .data_inputs
                    .iter()
                    .map(|di| *di.box_id.as_bytes())
            })
            .collect();

        // Parent state root = the committed tip digest (linear path).
        let parent_state_root = self.root_digest();

        // Verify: root-hash gate + section-id gate + parent-seed +
        // lookups-then-removes-asc-then-inserts-asc replay + finalize +
        // cross-check computed == header.state_root. Every rejection is
        // treated as SESSION-scoped: mark the header invalid for this
        // session and refuse the block, without persisting invalidity
        // (the repo invariant is that only PoW invalidity persists).
        let new_root = match crate::digest_apply::DigestProofVerifier::apply_block_in_memory(
            ad_proofs_id,
            &ad_proofs.proof_bytes,
            header,
            &parent_state_root,
            &to_lookup,
            &to_remove,
            &to_insert,
        ) {
            Ok(root) => root,
            Err(e) => {
                self.session_invalids.insert(header_id);
                return Err(StateError::DigestApplyRejected {
                    header_id: header_id_hex,
                    reason: e.to_string(),
                });
            }
        };

        // Linear applicability (height == tip+1 AND parent == tip) was
        // established by the preflights above. Header acceptance has
        // already advanced `best_header_*` (the header is validated
        // before its full block), so applying the full block advances
        // only `best_full_block_*`. `apply_block_digest` enforces
        // height == prev+1, the `best_header >= best_full_block` shape
        // invariant, and epoch-boundary voted-params keying, then
        // commits atomically and refreshes the cached params — it does
        // NOT re-check parent identity, which is why the preflight
        // above owns that gate.
        let mut new_chain_state = self.chain_state.clone();
        new_chain_state.best_full_block_id = header_id;
        new_chain_state.best_full_block_height = new_height;

        self.apply_block_digest(new_root, new_chain_state, voted_params_row)
    }

    fn rollback_to(
        &mut self,
        target_height: u32,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
        rescan_guard: Option<&dyn crate::wallet::apply::RescanGuard>,
    ) -> Result<(), StateError> {
        // Same contract as apply: the digest backend has no wallet /
        // rescan pipeline, so a non-`None` hook or guard is a wiring
        // bug rather than something to silently ignore.
        if wallet_hook.is_some() || rescan_guard.is_some() {
            return Err(StateError::InvalidPrecondition {
                what: "digest backend received a wallet hook/rescan guard; Mode 5 has no wallet pipeline",
            });
        }
        DigestStateStore::rollback_to(self, target_height)
    }
}

/// Result of `read_consistent_state`: the reconstructed in-memory
/// pair plus whether the dir had no committed state (Shape 1). The
/// `fresh` flag drives the voted-params genesis decision — seed on
/// fresh, require-present on committed.
struct LoadedState {
    root_digest: [u8; 33],
    chain_state: ChainStateMeta,
    fresh: bool,
}

/// Reconstruct the in-memory `(root_digest, chain_state)` pair from
/// disk, treating `CHAIN_STATE_META["chain_state"]` as the
/// authoritative anchor and cross-checking the other two rows
/// against it.
///
/// Three on-disk shapes are valid; everything else is corruption:
///
/// 1. **Fresh** — `chain_state` absent. No apply ever committed, so
///    `root_digest` and `CHAIN_INDEX` must also be empty. Boots at
///    the network's genesis state (`genesis_state_digest`).
/// 2. **Genesis-after-rollback** — `chain_state` present with
///    `best_full_block_height == 0` (the store applied blocks then
///    rolled back to 0). `root_digest` is present and must equal
///    `genesis_state_digest`, and `CHAIN_INDEX` carries no
///    applied-height rows (`apply` only writes rows at height >= 1,
///    and rollback truncated them).
/// 3. **Applied** — `chain_state` present with height `h >= 1`.
///    `root_digest` present; `CHAIN_INDEX` tip height equals `h`
///    AND the id stored at that tip equals `best_full_block_id`
///    (apply writes them together; a divergence is a split-brain).
///    The applied root may equal `genesis_state_digest` (an empty
///    block changes no boxes) or differ from it, so the digest value
///    itself is not a corruption signal here — the tip/density
///    cross-checks below catch torn writes.
fn read_consistent_state(
    db: &Database,
    genesis_state_digest: &[u8; 33],
) -> Result<LoadedState, StateError> {
    let read = db.begin_read()?;
    let root = match read.open_table(crate::store::STATE_META) {
        Ok(meta) => match meta.get(ROOT_DIGEST_KEY)? {
            Some(v) => Some(decode_33_bytes(v.value(), "state_meta", ROOT_DIGEST_KEY)?),
            None => None,
        },
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(e) => return Err(e.into()),
    };
    let chain_state = match read.open_table(crate::store::CHAIN_STATE_META) {
        Ok(meta) => match meta.get(CHAIN_STATE_KEY)? {
            Some(v) => Some(ChainStateMeta::deserialize(v.value()).map_err(|e| {
                StateError::DbCorruption {
                    table: "chain_state_meta",
                    key: CHAIN_STATE_KEY.into(),
                    reason: format!("{e:?}"),
                }
            })?),
            None => None,
        },
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(e) => return Err(e.into()),
    };
    // Tip as (height, header_id) so the applied-shape check can
    // catch a tip-id split-brain, not just a height mismatch.
    let chain_index_tip: Option<(u32, [u8; 32])> = match read.open_table(crate::store::CHAIN_INDEX)
    {
        Ok(idx) => match idx.iter()?.next_back() {
            Some(Ok((k, v))) => {
                let id = decode_32_bytes(v.value(), "chain_index")?;
                Some((k.value() as u32, id))
            }
            Some(Err(e)) => return Err(e.into()),
            None => None,
        },
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(e) => return Err(e.into()),
    };

    let corruption = |reason: String| StateError::DbCorruption {
        table: "digest_state",
        key: "consistency".into(),
        reason,
    };

    match chain_state {
        // Shape 1: fresh. chain_state absent ⇒ no apply ever
        // committed, so EVERY other applied-state row must also be
        // absent — including the two history ledgers. Checking the
        // ledgers here closes the gap where a torn write loses
        // chain_state/root/index but leaves orphan history rows,
        // which would otherwise boot as genesis and silently discard
        // an applied chain.
        None => {
            let has_history = history_ledger_nonempty(&read)?;
            if root.is_some() || chain_index_tip.is_some() || has_history {
                return Err(corruption(format!(
                    "chain_state absent but root_digest={} / chain_index_tip={} / \
                     history_rows={} present — torn write or external corruption \
                     (not a genuinely fresh store)",
                    root.is_some(),
                    chain_index_tip.is_some(),
                    has_history,
                )));
            }
            Ok(LoadedState {
                root_digest: *genesis_state_digest,
                chain_state: genesis_chain_state(),
                fresh: true,
            })
        }
        Some(cs) => {
            // chain_state is authoritative — root_digest must accompany it.
            let root = root.ok_or_else(|| {
                corruption("chain_state present but root_digest absent — torn write".into())
            })?;
            // Internal fork-choice invariants on the persisted chain
            // state (header tip leads/equals full-block tip; score
            // non-empty). A violation is on-disk corruption.
            if let Err(reason) = chain_state_internal_invariant(&cs) {
                return Err(corruption(reason.into()));
            }
            let h = cs.best_full_block_height;
            if h == 0 {
                // Shape 2: genesis-after-rollback. CHAIN_INDEX carries
                // no applied-height rows; the root is the empty digest;
                // and rollback-to-0 leaves the genesis history rows
                // (key 0) it read to restore. A `chain_state` at
                // height 0 can only arise from a rollback, so those
                // rows must exist — their absence is a torn write.
                if let Some((tip_h, _)) = chain_index_tip {
                    return Err(corruption(format!(
                        "chain_state at genesis (height 0) but chain_index has tip {tip_h}"
                    )));
                }
                if &root != genesis_state_digest {
                    return Err(corruption(format!(
                        "chain_state at genesis (height 0) but root_digest {} != the \
                         network's genesis digest",
                        hex::encode(root),
                    )));
                }
                // Rollback-to-0 leaves history[0] (the row it read to
                // restore); a chain_state at height 0 can only arise
                // from a rollback, so the genesis substrate must exist.
                require_history_dense_through(&read, 0)?;
                // Cross-network mis-open guard: the persisted genesis
                // row must equal the supplied genesis digest, else this
                // dir belongs to a different network than the one we
                // were opened for.
                require_genesis_history_matches(&read, genesis_state_digest)?;
                Ok(LoadedState {
                    root_digest: root,
                    chain_state: cs,
                    fresh: false,
                })
            } else {
                // Shape 3: applied. Tip height AND id must match, and
                // the rollback substrate (history dense over [0, h-1])
                // must exist — otherwise the store boots "healthy" but
                // cannot reorg, surfacing the defect at a fork instead
                // of at open. The stored root itself is anchored to the
                // tip header's committed `state_root` back in `open`
                // (once the header store is built), so a root mutated to
                // any plausible value — the genesis digest included — is
                // rejected there; here the tip-id split-brain and density
                // cross-checks catch the structural torn writes.
                let (tip_h, tip_id) = chain_index_tip.ok_or_else(|| {
                    corruption(format!("chain_state height {h} but chain_index is empty"))
                })?;
                if tip_h != h {
                    return Err(corruption(format!(
                        "height mismatch: chain_state {h} != chain_index tip {tip_h}"
                    )));
                }
                if tip_id != cs.best_full_block_id {
                    return Err(corruption(format!(
                        "tip-id split-brain: chain_index[{tip_h}] = {} != best_full_block_id {}",
                        hex::encode(tip_id),
                        hex::encode(cs.best_full_block_id),
                    )));
                }
                // The full rollback substrate must be dense over
                // `[0, h-1]`: a hole anywhere below the tip would
                // boot clean and only fail at a reorg deep enough to
                // reach it.
                require_history_dense_through(&read, (h - 1) as u64)?;
                // CHAIN_INDEX must be dense over `[1, h]` — a hole
                // below the tip (the tip alone matched above) is a
                // torn write on a shared load-bearing table.
                require_chain_index_dense(&read, h)?;
                // Cross-network mis-open guard: density above guarantees
                // history[0] exists; it must equal the supplied genesis
                // digest, else this committed dir belongs to a different
                // network. Caught here at open, not at a deep rollback.
                require_genesis_history_matches(&read, genesis_state_digest)?;
                Ok(LoadedState {
                    root_digest: root,
                    chain_state: cs,
                    fresh: false,
                })
            }
        }
    }
}

/// Assert that `DIGEST_HISTORY[0]` (the genesis substrate row) equals
/// the `genesis_state_digest` the store was opened for. A mismatch
/// means the dir was committed under a different network's genesis and
/// is being mis-opened — caught at open rather than surfacing only when
/// a reorg reaches height 0. Callers must have already established that
/// the row exists (via the density check), so its absence here is
/// itself corruption.
fn require_genesis_history_matches(
    read: &redb::ReadTransaction,
    genesis_state_digest: &[u8; 33],
) -> Result<(), StateError> {
    let table = read.open_table(DIGEST_HISTORY)?;
    let row = table.get(0u64)?.ok_or(StateError::DbCorruption {
        table: "digest_history",
        key: "0".into(),
        reason: "genesis substrate row absent after density check passed".into(),
    })?;
    let stored = decode_33_bytes(row.value(), "digest_history", "0")?;
    if &stored != genesis_state_digest {
        return Err(StateError::DbCorruption {
            table: "digest_history",
            key: "0".into(),
            reason: format!(
                "genesis digest_history[0] = {} != the genesis digest this store was \
                 opened for ({}) — wrong-network or corrupted dir",
                hex::encode(stored),
                hex::encode(genesis_state_digest),
            ),
        });
    }
    Ok(())
}

/// Cross-check that a root we are about to trust — the stored tip root
/// at open, or a snapshot root a rollback is about to install live —
/// equals the `state_root` the tip block's header commits to. The header
/// is the consensus-authenticated commitment to the post-apply digest,
/// so a stored root that disagrees with it is corruption: a mutated
/// `STATE_META[root_digest]` or `DIGEST_HISTORY[h]` (even one that happens
/// to equal the genesis digest) would otherwise be accepted, and the node
/// would boot or reorg onto the wrong parent root and then reject honest
/// follow-on blocks. This anchor is what makes the root-value check the
/// genesis seed displaced safe: instead of guessing whether `root ==
/// genesis` at an applied height is a torn write or a real empty block, it
/// asks the header, which knows.
///
/// An applied tip cannot exist without its header — the full block is
/// verified against that header's `state_root` before it commits — so a
/// missing header here is itself corruption, not a benign absence.
fn require_root_matches_tip_header(
    headers: &crate::header_store::HeaderSectionTables,
    tip_header_id: &[u8; 32],
    expected_root: &[u8; 33],
) -> Result<(), StateError> {
    let header_bytes =
        headers
            .get_header(tip_header_id)?
            .ok_or_else(|| StateError::DbCorruption {
                table: "headers",
                key: hex::encode(tip_header_id),
                reason: "applied tip has no stored header — cannot anchor the \
                     persisted state root to its consensus commitment"
                    .into(),
            })?;
    let mut reader = ergo_primitives::reader::VlqReader::new(&header_bytes);
    let header =
        ergo_ser::header::read_header(&mut reader).map_err(|e| StateError::DbCorruption {
            table: "headers",
            key: hex::encode(tip_header_id),
            reason: format!("stored tip header failed to parse: {e:?}"),
        })?;
    if header.state_root.as_bytes() != expected_root {
        return Err(StateError::DbCorruption {
            table: "state_meta",
            key: "root_digest".into(),
            reason: format!(
                "persisted root {} disagrees with tip header {} state_root {} \
                 — torn write or external mutation of the stored root",
                hex::encode(expected_root),
                hex::encode(tip_header_id),
                hex::encode(header.state_root.as_bytes()),
            ),
        });
    }
    Ok(())
}

/// Assert that both height-indexed history ledgers are DENSE over
/// `[0, through]` — every key `0..=through` present, no holes. This
/// is the full rollback substrate: a rollback to any height `j <=
/// through` reads `history[j]`, so a hole anywhere below the tip
/// would boot "healthy" yet fail at a deep reorg that reaches it.
/// Checking only the immediate parent (`through`) is not enough.
///
/// Verified in O(log n) via `first`/`last`/`len`: density over
/// `[first, last]` holds iff `len == last - first + 1`; we then
/// require `first == 0` and `last >= through`. After a forward apply
/// to height `h` the keyset is `{0..h-1}` (`through = h-1`); after a
/// rollback to `K` it is `{0..K}` (the redundant key `K == h` sits
/// at `last` and is covered by the same density check). Both shapes
/// satisfy the invariant.
///
/// Surfaces `DbCorruption` naming the specific ledger so the operator
/// sees the missing rollback substrate at open, not at the first
/// reorg.
fn require_history_dense_through(
    read: &redb::ReadTransaction,
    through: u64,
) -> Result<(), StateError> {
    for (table_def, name) in [
        (DIGEST_HISTORY, "digest_history"),
        (CHAIN_STATE_HISTORY, "chain_state_history"),
    ] {
        let table = match read.open_table(table_def) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Err(StateError::DbCorruption {
                    table: name,
                    key: format!("0..={through}"),
                    reason: "rollback substrate missing — history ledger absent on an \
                         applied store (apply co-writes it every block)"
                        .into(),
                });
            }
            Err(e) => return Err(e.into()),
        };
        let len = table.len()?;
        let first = table.first()?.map(|(k, _)| k.value());
        let last = table.last()?.map(|(k, _)| k.value());
        let corrupt = |reason: String| StateError::DbCorruption {
            table: name,
            key: format!("0..={through}"),
            reason,
        };
        match (first, last) {
            (Some(first), Some(last)) => {
                if first != 0 {
                    return Err(corrupt(format!(
                        "history does not start at 0 (first key = {first}) — \
                         rollback substrate truncated below genesis"
                    )));
                }
                if last < through {
                    return Err(corrupt(format!(
                        "history top key {last} < required parent height {through} — \
                         rollback substrate missing for a torn-write tip"
                    )));
                }
                if len != last + 1 {
                    return Err(corrupt(format!(
                        "history has holes: {len} rows but keys span 0..={last} \
                         (expected {} contiguous rows)",
                        last + 1
                    )));
                }
            }
            _ => {
                return Err(corrupt(
                    "rollback substrate missing — history ledger empty on an applied \
                     store"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

/// True if EITHER history ledger holds any row. Used by the fresh-
/// store shape check: a genuinely fresh dir has empty ledgers, so a
/// non-empty ledger alongside an absent `chain_state` is a torn
/// applied store, not a fresh one.
fn history_ledger_nonempty(read: &redb::ReadTransaction) -> Result<bool, StateError> {
    for table_def in [DIGEST_HISTORY, CHAIN_STATE_HISTORY] {
        let present = match read.open_table(table_def) {
            Ok(t) => t.first()?.is_some(),
            Err(redb::TableError::TableDoesNotExist(_)) => false,
            Err(e) => return Err(e.into()),
        };
        if present {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Assert `CHAIN_INDEX` is dense over `[1, height]`. Apply writes one
/// row per applied height `1..=h` and rollback truncates the suffix,
/// so the index is contiguous from 1 to the tip; the tip's height is
/// always the current height (no rolled-back redundancy as the
/// history ledgers have), so the check is exact. A hole below the
/// tip is a torn write on a shared load-bearing table.
fn require_chain_index_dense(read: &redb::ReadTransaction, height: u32) -> Result<(), StateError> {
    let table = match read.open_table(crate::store::CHAIN_INDEX) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(StateError::DbCorruption {
                table: "chain_index",
                key: format!("1..={height}"),
                reason: "chain_index absent on an applied store".into(),
            });
        }
        Err(e) => return Err(e.into()),
    };
    let len = table.len()?;
    let first = table.first()?.map(|(k, _)| k.value());
    let last = table.last()?.map(|(k, _)| k.value());
    let h = height as u64;
    if first != Some(1) || last != Some(h) || len != h {
        return Err(StateError::DbCorruption {
            table: "chain_index",
            key: format!("1..={height}"),
            reason: format!(
                "chain_index not dense over [1, {height}]: first={first:?}, last={last:?}, \
                 len={len} (expected first=1, last={height}, len={height})"
            ),
        });
    }
    Ok(())
}

/// Canonical genesis chain state for a fresh digest store. Reuses
/// `ChainState::empty()` (the crate-wide pre-genesis state) so the
/// digest backend's genesis matches the UTXO backend byte-for-byte
/// — notably `best_header_score = [0]`, not an empty vec.
fn genesis_chain_state() -> ChainStateMeta {
    crate::chain::ChainState::empty().to_persisted()
}

/// Internal fork-choice invariants every `ChainStateMeta` the store
/// accepts must satisfy, independent of any header store:
/// - `best_header_height >= best_full_block_height` — headers are
///   validated before the full blocks they cover, so the header tip
///   can never trail the full-block tip.
/// - `best_header_score` is non-empty — even genesis carries `[0]`.
///
/// Returns a static reason on violation so callers can route it to
/// `InvalidPrecondition` (caller-supplied state) or `DbCorruption`
/// (on-disk state). This does NOT validate `best_header_*` against
/// persisted header rows — that needs header tables this sibling
/// does not own.
fn chain_state_internal_invariant(cs: &ChainStateMeta) -> Result<(), &'static str> {
    if cs.best_header_height < cs.best_full_block_height {
        return Err("chain state best_header_height < best_full_block_height \
             (headers must lead or equal full blocks)");
    }
    if cs.best_header_score.is_empty() {
        return Err("chain state best_header_score is empty (must be non-empty)");
    }
    Ok(())
}

fn decode_33_bytes(bytes: &[u8], table: &'static str, key: &str) -> Result<[u8; 33], StateError> {
    if bytes.len() != 33 {
        return Err(StateError::DbCorruption {
            table,
            key: key.into(),
            reason: format!("must be 33 bytes; got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn decode_32_bytes(bytes: &[u8], table: &'static str) -> Result<[u8; 32], StateError> {
    if bytes.len() != 32 {
        return Err(StateError::DbCorruption {
            table,
            key: "tip".into(),
            reason: format!("header id must be 32 bytes; got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn read_digest_history_row(db: &Database, height: u32) -> Result<[u8; 33], StateError> {
    let read = db.begin_read()?;
    let table = read.open_table(DIGEST_HISTORY)?;
    let row = table
        .get(height as u64)?
        .ok_or(StateError::DigestHistoryMissing { height })?;
    decode_33_bytes(row.value(), "digest_history", &format!("{height}"))
}

/// Read the `best_full_block_id` recorded at `height` in
/// `CHAIN_INDEX`. Used by `rollback_to` to cross-check the restored
/// snapshot against the row that becomes the post-rollback tip.
fn read_chain_index_id(db: &Database, height: u32) -> Result<[u8; 32], StateError> {
    let read = db.begin_read()?;
    let table = read.open_table(crate::store::CHAIN_INDEX)?;
    let row = table.get(height as u64)?.ok_or(StateError::DbCorruption {
        table: "chain_index",
        key: format!("{height}"),
        reason: "rollback target has no chain_index row".into(),
    })?;
    decode_32_bytes(row.value(), "chain_index")
}

fn read_chain_state_history_row(db: &Database, height: u32) -> Result<ChainStateMeta, StateError> {
    let read = db.begin_read()?;
    let table = read.open_table(CHAIN_STATE_HISTORY)?;
    let row = table
        .get(height as u64)?
        .ok_or(StateError::DigestHistoryMissing { height })?;
    ChainStateMeta::deserialize(row.value()).map_err(|e| StateError::DbCorruption {
        table: "chain_state_history",
        key: format!("{height}"),
        reason: format!("{e:?}"),
    })
}

fn truncate_above_height(
    txn: &redb::WriteTransaction,
    table_def: TableDefinition<u64, &[u8]>,
    target_height: u32,
) -> Result<(), StateError> {
    let mut t = txn.open_table(table_def)?;
    let lower = (target_height as u64).saturating_add(1);
    // Collect the keys to remove first (can't delete while the
    // range iterator borrows the table). Iterator errors propagate
    // — a swallowed read error here would leave rows above the
    // target and still commit the rollback, corrupting the suffix.
    let mut to_remove: Vec<u64> = Vec::new();
    for entry in t.range(lower..=u64::MAX)? {
        let (k, _) = entry?;
        to_remove.push(k.value());
    }
    for h in to_remove {
        t.remove(h)?;
    }
    Ok(())
}

/// Fresh-dir genesis voted-params baseline with a cross-network guard.
///
/// On a NEVER-APPLIED dir the genesis digest is not yet persisted (it
/// lives in memory until the first apply writes `DIGEST_HISTORY[0]`), so
/// the committed-store wrong-network guard has no anchor here. The one
/// row a prior fresh open persisted is `VOTED_PARAMS[0]` — the launch
/// baseline. If it is already present it MUST equal the launch params
/// for the network this store is being opened for; a mismatch means the
/// dir was initialized for a different network (e.g. a mainnet dir
/// reopened as testnet before any block applied), and silently reusing
/// the stale row would validate against the wrong protocol baseline.
/// Absent ⇒ seed it (first-ever open).
fn require_genesis_voted_params_match_or_seed(
    db: &Database,
    launch: &ActiveProtocolParameters,
) -> Result<(), StateError> {
    let read = db.begin_read()?;
    let existing = match read.open_table(crate::active_params::VOTED_PARAMS) {
        Ok(t) => match t.get(0u64)? {
            Some(v) => Some(
                ActiveProtocolParameters::deserialize(v.value()).map_err(|e| {
                    StateError::DbCorruption {
                        table: "voted_params",
                        key: "0".into(),
                        reason: format!("genesis voted-params row decode failed: {e:?}"),
                    }
                })?,
            ),
            None => None,
        },
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(e) => return Err(e.into()),
    };
    drop(read);
    if let Some(existing) = existing {
        if &existing != launch {
            return Err(StateError::DbCorruption {
                table: "voted_params",
                key: "0".into(),
                reason: "fresh digest-verifier dir already carries a genesis \
                     voted-params row that does not match this network's launch \
                     parameters — the dir was initialized for a different network \
                     and is being reopened before any block applied; refusing to \
                     run validation against the wrong protocol baseline"
                    .into(),
            });
        }
        return Ok(());
    }
    let write_txn = crate::begin_write_qr(db)?;
    active_params::insert(&write_txn, launch).map_err(|e| StateError::VotedParamsWriteFailed {
        op: "digest-store genesis seed",
        height: 0,
        source: Box::new(e),
    })?;
    write_txn.commit()?;
    Ok(())
}

/// True if the dir carries `DigestStateStore`-exclusive on-disk
/// markers — its history ledger or the `root_digest` meta key. Used
/// by `verify_or_init_state_type_inner` to refuse re-stamping a
/// digest-verifier dir whose `data_dir_state_type` sentinel was lost
/// to partial corruption as `"utxo"` / `"digest"`. A fresh (never
/// applied) digest-verifier dir has neither marker, but it is also
/// genuinely empty, so re-stamping it is harmless.
pub(crate) fn has_digest_verifier_markers(db: &Database) -> Result<bool, StateError> {
    let read = db.begin_read()?;
    // Both history ledgers are digest-verifier-exclusive tables.
    // Checking both (not just `DIGEST_HISTORY`) closes the gap where
    // a torn write loses one ledger and the `root_digest` key but
    // leaves the other ledger, which would otherwise read as "no
    // markers" and allow a mis-stamp.
    for table_def in [DIGEST_HISTORY, CHAIN_STATE_HISTORY] {
        let present = match read.open_table(table_def) {
            Ok(t) => t.first()?.is_some(),
            Err(redb::TableError::TableDoesNotExist(_)) => false,
            Err(e) => return Err(e.into()),
        };
        if present {
            return Ok(true);
        }
    }
    let has_root_digest = match read.open_table(crate::store::STATE_META) {
        Ok(t) => t.get(ROOT_DIGEST_KEY)?.is_some(),
        Err(redb::TableError::TableDoesNotExist(_)) => false,
        Err(e) => return Err(e.into()),
    };
    Ok(has_root_digest)
}

/// On a store that already has committed state, the genesis
/// voted-params row (height 0) must be present. Its absence would
/// let `read_latest_at` silently fall back to a later epoch's
/// parameters, drifting validation settings — so a missing row is
/// loud `DbCorruption`, never a silent re-seed.
fn require_genesis_voted_params_present(db: &Database) -> Result<(), StateError> {
    let read = db.begin_read()?;
    let present = match read.open_table(crate::active_params::VOTED_PARAMS) {
        Ok(t) => t.get(0u64)?.is_some(),
        Err(redb::TableError::TableDoesNotExist(_)) => false,
        Err(e) => return Err(e.into()),
    };
    if !present {
        return Err(StateError::DbCorruption {
            table: "voted_params",
            key: "0".into(),
            reason: "genesis voted-params row absent on a store with committed state \
                 — losing it would silently change active protocol parameters after \
                 restart; refusing to re-seed over committed history"
                .into(),
        });
    }
    Ok(())
}

/// Validate the shape of the `VOTED_PARAMS` keyset: every key must be
/// the genesis baseline (0) or a real epoch boundary (a positive
/// multiple of `voting_length`) at or below the committed tip. This
/// catches orphan rows above the tip and off-boundary rows from a
/// torn write or external mutation.
///
/// It does NOT detect a MISSING intermediate epoch row — whether a
/// given boundary should carry a row depends on whether parameters
/// changed there, which is encoded in block-section extensions this
/// sibling does not store. That continuity check belongs with the
/// section-reconcile machinery (Mode 1's `reconcile_voted_params`).
fn validate_voted_params_keys(
    db: &Database,
    tip_height: u32,
    voting_length: u32,
) -> Result<(), StateError> {
    let read = db.begin_read()?;
    let table = match read.open_table(crate::active_params::VOTED_PARAMS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let vl = voting_length as u64;
    let tip = tip_height as u64;
    for entry in table.iter()? {
        let (k, val) = entry?;
        let key = k.value();
        // Payload integrity: the row must decode AND its embedded
        // `epoch_start_height` must equal its key. A decode failure
        // or key/embedded mismatch is corruption that `read_latest_at`
        // would otherwise only surface lazily on the first read.
        let params =
            ergo_validation::ActiveProtocolParameters::deserialize(val.value()).map_err(|e| {
                StateError::DbCorruption {
                    table: "voted_params",
                    key: format!("{key}"),
                    reason: format!("voted_params row failed to decode: {e:?}"),
                }
            })?;
        if params.epoch_start_height as u64 != key {
            return Err(StateError::DbCorruption {
                table: "voted_params",
                key: format!("{key}"),
                reason: format!(
                    "voted_params row embedded epoch_start_height {} != row key {key}",
                    params.epoch_start_height
                ),
            });
        }
        if key == 0 {
            continue; // genesis baseline
        }
        let on_boundary = vl > 0 && key.is_multiple_of(vl);
        if !on_boundary || key > tip {
            return Err(StateError::DbCorruption {
                table: "voted_params",
                key: format!("{key}"),
                reason: format!(
                    "voted_params key {key} is not a valid epoch boundary at or below \
                     the committed tip {tip_height} (voting_length {voting_length}) — \
                     orphan or off-boundary row"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
