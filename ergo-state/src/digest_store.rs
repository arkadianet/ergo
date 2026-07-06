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
//! C-2 is the apply-bridge that anchors the persisted digest to a
//! header's `state_root`: that needs the ADProofs section, the
//! boxChanges derivation, and the 5.7 oracle, none of which this
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
        // the shared trait for the non-incident path.
        self.session_invalids.insert(header_id);
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
mod tests {
    use super::*;
    use crate::backend::{ChainStateRead, HeaderSectionStore};
    use crate::chain::HeaderAvailability;
    use ergo_validation::scala_launch;
    use std::path::Path;
    use tempfile::tempdir;

    // ----- helpers -----

    /// Test voting cadence with a short epoch length (2). Heights
    /// 2, 4, 6, … are epoch boundaries; 1, 3, 5, … are not — letting
    /// the voted-params boundary guard be exercised on both sides
    /// without mainnet's 1024-block epoch.
    fn test_voting() -> ergo_chain_spec::VotingParams {
        ergo_chain_spec::VotingParams {
            voting_length: 2,
            ..ergo_chain_spec::VotingParams::mainnet()
        }
    }

    fn open_at(dir: &Path) -> DigestStateStore {
        let path = dir.join("digest_state.redb");
        open_at_path(&path)
    }

    /// Synthetic genesis digest for the unit tests below. The synth
    /// apply/rollback helpers fabricate arbitrary digests and expect
    /// rollback-to-0 to restore this fixed height-0 value, so the tests
    /// seed the store with it rather than a real network digest. Equal
    /// to `EMPTY_AVL_DIGEST` so the historical `== EMPTY_AVL_DIGEST`
    /// assertions read naturally as "back at the genesis seed".
    const TEST_GENESIS_DIGEST: [u8; 33] = EMPTY_AVL_DIGEST;

    fn open_at_path(db_path: &Path) -> DigestStateStore {
        DigestStateStore::open(db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
            .expect("DigestStateStore::open")
    }

    fn synth_digest(seed: u32) -> [u8; 33] {
        let mut out = [0u8; 33];
        let seed_bytes = seed.to_be_bytes();
        for (i, b) in out.iter_mut().enumerate() {
            *b = seed_bytes[i % 4].wrapping_add(i as u8 + 1);
        }
        out
    }

    fn synth_header_id(seed: u32) -> [u8; 32] {
        let mut out = [0u8; 32];
        let seed_bytes = seed.to_be_bytes();
        for (i, b) in out.iter_mut().enumerate() {
            *b = seed_bytes[i % 4] ^ (i as u8);
        }
        out
    }

    /// Synth ChainStateMeta at height `h` — header_id, score, and
    /// full-block-id derived from `h`. best_header and
    /// best_full_block both point at the same value (no fork in
    /// these tests).
    fn synth_chain_state(h: u32) -> ChainStateMeta {
        let id = synth_header_id(h);
        let score = (h as u64).to_be_bytes().to_vec();
        ChainStateMeta {
            best_header_id: id,
            best_header_height: h,
            best_header_score: score,
            best_full_block_id: id,
            best_full_block_height: h,
            header_availability: HeaderAvailability::Dense,
        }
    }

    /// Serialized v2 header committing `state_root`, keyed (by the caller)
    /// under `synth_header_id(h)`. The open/rollback root-anchor reads only
    /// `state_root`, so the other fields are plausible filler; the bytes
    /// must round-trip through `read_header`, which a v2 header with an
    /// empty `unparsed_bytes` and a stored (unvalidated) group element does
    /// (see `ergo_ser::header::tests::header_v2_roundtrips`).
    fn synth_header_bytes(h: u32, state_root: [u8; 33]) -> Vec<u8> {
        use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::header::{serialize_header, Header};
        let parent_id = if h <= 1 {
            [0u8; 32]
        } else {
            synth_header_id(h - 1)
        };
        let header = Header {
            version: 2,
            parent_id: ModifierId::from_bytes(parent_id),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes(state_root),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            timestamp: 1_700_000_000,
            n_bits: 0x1d00_ffff,
            height: h,
            extension_root: Digest32::from_bytes([0u8; 32]),
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xAA; 8],
            },
        };
        let (bytes, _) = serialize_header(&header).expect("serialize_header");
        bytes
    }

    /// Store the tip header the open/rollback root-anchor will check, then
    /// apply the digest block through the raw seam. The header's
    /// `state_root` is the committed root, keyed by the chain-state's
    /// `best_full_block_id`, so a later reopen or rollback to this tip
    /// finds a header its stored root reconciles against. `apply_synth` is
    /// the common (synth id, no voted-params) case; tests that drive a
    /// custom chain-state or a voted-params row call this directly.
    fn apply_digest_with_header(
        store: &mut DigestStateStore,
        root: [u8; 33],
        chain_state: ChainStateMeta,
        voted: Option<ActiveProtocolParameters>,
    ) {
        let height = chain_state.best_full_block_height;
        let header_bytes = synth_header_bytes(height, root);
        HeaderSectionStore::store_header(store, &chain_state.best_full_block_id, &header_bytes)
            .expect("store tip header");
        store
            .apply_block_digest(root, chain_state, voted)
            .unwrap_or_else(|e| panic!("apply at height {height}: {e}"));
    }

    fn apply_synth(store: &mut DigestStateStore, h: u32) {
        apply_digest_with_header(store, synth_digest(h), synth_chain_state(h), None);
    }

    // ----- happy path -----

    #[test]
    fn fresh_open_initializes_to_genesis() {
        let tmp = tempdir().expect("tempdir");
        let store = open_at(tmp.path());
        assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
        assert_eq!(store.height(), 0);
        assert_eq!(store.chain_state().best_header_height, 0);
        assert_eq!(store.chain_state().best_header_id, [0u8; 32]);
    }

    #[test]
    fn fresh_open_seeds_the_supplied_genesis_digest() {
        // The fresh-store root is whatever genesis digest the network
        // supplies, NOT the all-zero sentinel. Seed with mainnet's real
        // genesis root and confirm the store boots with it — this is the
        // value Mode 5 verifies block 1 against.
        let mainnet_genesis = ergo_chain_spec::GenesisParams::mainnet().state_digest;
        assert_ne!(mainnet_genesis, EMPTY_AVL_DIGEST);
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("digest_state.redb");
        let store = DigestStateStore::open(&path, scala_launch(), test_voting(), mainnet_genesis)
            .expect("open");
        assert_eq!(store.root_digest(), mainnet_genesis);
        assert_eq!(store.height(), 0);
    }

    #[test]
    fn rollback_to_genesis_restores_supplied_genesis_digest() {
        // After applying synth blocks on a store seeded with a real
        // genesis digest, rollback-to-0 must restore exactly that
        // digest — DIGEST_HISTORY[0] holds the genesis root.
        let mainnet_genesis = ergo_chain_spec::GenesisParams::mainnet().state_digest;
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("digest_state.redb");
        let mut store =
            DigestStateStore::open(&path, scala_launch(), test_voting(), mainnet_genesis)
                .expect("open");
        for h in 1u32..=3 {
            apply_synth(&mut store, h);
        }
        store.rollback_to(0).expect("rollback to genesis");
        assert_eq!(store.root_digest(), mainnet_genesis);
        assert_eq!(store.height(), 0);
    }

    #[test]
    fn fresh_genesis_matches_crate_canonical_empty_state() {
        // The digest backend's genesis must be byte-identical to the
        // crate-wide `ChainState::empty()` — notably
        // `best_header_score == [0]`, NOT an empty vec. A divergence
        // would make the two backends disagree on the pre-genesis
        // score encoding.
        let tmp = tempdir().expect("tempdir");
        let store = open_at(tmp.path());
        let canonical = crate::chain::ChainState::empty().to_persisted();
        assert_eq!(
            store.chain_state().best_header_score,
            canonical.best_header_score,
        );
        assert_eq!(store.chain_state().best_header_score, vec![0]);
        assert_eq!(store.chain_state().best_header_id, canonical.best_header_id);
        assert_eq!(
            store.chain_state().best_full_block_height,
            canonical.best_full_block_height,
        );
    }

    #[test]
    fn apply_advances_root_chain_state_and_height() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        apply_synth(&mut store, 1);
        assert_eq!(store.root_digest(), synth_digest(1));
        assert_eq!(store.height(), 1);
        assert_eq!(store.chain_state().best_full_block_id, synth_header_id(1));
    }

    // ----- round-trips -----

    #[test]
    fn apply_persists_across_reopen() {
        let tmp = tempdir().expect("tempdir");
        {
            let mut store = open_at(tmp.path());
            apply_synth(&mut store, 1);
        }
        let store = open_at(tmp.path());
        assert_eq!(store.root_digest(), synth_digest(1));
        assert_eq!(store.height(), 1);
        assert_eq!(store.chain_state().best_full_block_id, synth_header_id(1));
    }

    #[test]
    fn sequential_applies_advance_through_multiple_heights() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        for h in 1u32..=5 {
            apply_synth(&mut store, h);
            assert_eq!(store.height(), h);
            assert_eq!(store.root_digest(), synth_digest(h));
        }
    }

    #[test]
    fn rollback_restores_root_chain_state_at_target_height() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        for h in 1u32..=5 {
            apply_synth(&mut store, h);
        }
        store.rollback_to(3).expect("rollback");
        assert_eq!(store.height(), 3);
        assert_eq!(store.root_digest(), synth_digest(3));
        assert_eq!(store.chain_state().best_full_block_id, synth_header_id(3));
        assert_eq!(
            store.chain_state().best_header_score,
            (3u64).to_be_bytes().to_vec(),
        );
    }

    #[test]
    fn rollback_to_genesis_restores_empty_state() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        for h in 1u32..=3 {
            apply_synth(&mut store, h);
        }
        store.rollback_to(0).expect("rollback to genesis");
        assert_eq!(store.height(), 0);
        assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
        assert_eq!(store.chain_state().best_header_height, 0);
        // Genesis restores the canonical empty-state score ([0]),
        // matching `ChainState::empty()`.
        assert_eq!(store.chain_state().best_header_score, vec![0]);
    }

    #[test]
    fn rollback_to_genesis_then_reopen_boots_clean() {
        // The genesis-after-rollback on-disk shape: chain_state
        // present at height 0, root_digest present (= the genesis
        // seed), CHAIN_INDEX empty (rollback truncated all
        // applied-height rows). `read_consistent_state` must accept
        // this as a valid genesis state, NOT reject it as a torn write.
        let tmp = tempdir().expect("tempdir");
        {
            let mut store = open_at(tmp.path());
            for h in 1u32..=3 {
                apply_synth(&mut store, h);
            }
            store.rollback_to(0).expect("rollback to genesis");
        }
        let store = open_at(tmp.path());
        assert_eq!(store.height(), 0);
        assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
        assert_eq!(store.chain_state().best_header_score, vec![0]);
    }

    #[test]
    fn rollback_persists_across_reopen() {
        let tmp = tempdir().expect("tempdir");
        {
            let mut store = open_at(tmp.path());
            for h in 1u32..=4 {
                apply_synth(&mut store, h);
            }
            store.rollback_to(2).expect("rollback");
        }
        let store = open_at(tmp.path());
        assert_eq!(store.height(), 2);
        assert_eq!(store.root_digest(), synth_digest(2));
        assert_eq!(store.chain_state().best_full_block_id, synth_header_id(2));
    }

    #[test]
    fn rollback_then_reapply_reaches_same_tip_as_uninterrupted_path() {
        let tmp_straight = tempdir().expect("tempdir");
        let tmp_redo = tempdir().expect("tempdir");

        let mut straight = open_at(tmp_straight.path());
        for h in 1u32..=5 {
            apply_synth(&mut straight, h);
        }
        let straight_tip = (
            straight.root_digest(),
            straight.chain_state().best_full_block_id,
            straight.chain_state().best_full_block_height,
        );

        let mut redo = open_at(tmp_redo.path());
        for h in 1u32..=5 {
            apply_synth(&mut redo, h);
        }
        redo.rollback_to(2).expect("redo rollback");
        for h in 3u32..=5 {
            apply_synth(&mut redo, h);
        }
        let redo_tip = (
            redo.root_digest(),
            redo.chain_state().best_full_block_id,
            redo.chain_state().best_full_block_height,
        );
        assert_eq!(redo_tip, straight_tip);
    }

    // ----- error paths -----

    #[test]
    fn apply_out_of_order_rejected() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        let err = store
            .apply_block_digest(synth_digest(2), synth_chain_state(2), None)
            .expect_err("must reject out-of-order apply");
        let msg = format!("{err}");
        assert!(msg.contains("out of order"), "msg={msg}");
        assert!(msg.contains("expected next height 1"), "msg={msg}");
        assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
        assert_eq!(store.height(), 0);
    }

    #[test]
    fn rollback_beyond_tip_rejected() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        apply_synth(&mut store, 1);
        let err = store
            .rollback_to(5)
            .expect_err("must reject rollback beyond tip");
        let msg = format!("{err}");
        assert!(msg.contains("rollback target 5"), "msg={msg}");
        assert!(msg.contains("current tip 1"), "msg={msg}");
    }

    #[test]
    fn rollback_to_current_height_is_noop() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        for h in 1u32..=3 {
            apply_synth(&mut store, h);
        }
        let before = (store.root_digest(), store.height());
        store.rollback_to(3).expect("noop");
        assert_eq!((store.root_digest(), store.height()), before);
    }

    #[test]
    fn open_rejects_half_populated_store() {
        // Torn shape: STATE_META["root_digest"] present but
        // CHAIN_STATE_META["chain_state"] absent (and chain_state is
        // the authoritative anchor). Mirrors an external `redb`
        // mutation or a torn write.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let db =
                crate::redb_util::open_with_repair_logging(&db_path, "torn-write").expect("open");
            crate::store::verify_or_init_state_type_inner(&db, DIGEST_VERIFIER_STATE_TYPE)
                .expect("stamp");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut t = txn.open_table(crate::store::STATE_META).expect("open");
                t.insert(ROOT_DIGEST_KEY, &synth_digest(7)[..])
                    .expect("insert");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("torn write must reject");
        let msg = format!("{err}");
        assert!(msg.contains("chain_state"), "msg={msg}");
    }

    #[test]
    fn open_rejects_tip_id_split_brain() {
        // chain_state.best_full_block_height matches the CHAIN_INDEX
        // tip height, but the header id stored at that tip differs
        // from chain_state.best_full_block_id. The atomic commit
        // writes them together, so a divergence is corruption — open
        // must reject rather than boot a split-brain tip.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            apply_synth(&mut store, 1);
        }
        // Corrupt CHAIN_INDEX[1] to a different id than
        // chain_state.best_full_block_id (= synth_header_id(1)).
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut idx = txn
                    .open_table(crate::store::CHAIN_INDEX)
                    .expect("open chain_index");
                idx.insert(1u64, &[0xFFu8; 32][..])
                    .expect("overwrite tip id");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("split-brain tip must reject");
        let msg = format!("{err}");
        assert!(msg.contains("split-brain"), "msg={msg}");
    }

    #[test]
    fn open_rejects_applied_store_with_missing_rollback_substrate() {
        // A torn write commits chain_state@h + root + matching tip
        // but loses the history rows (the rollback substrate). The
        // old open path would boot "healthy" and only fail at the
        // first reorg; open must reject so the operator sees it now.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=2 {
                apply_synth(&mut store, h);
            }
        }
        // Drop the parent-height history rows (h-1 = 1) from both
        // ledgers, simulating a torn write / external mutation.
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
                dh.remove(1u64).expect("remove digest_history[1]");
                let mut ch = txn
                    .open_table(CHAIN_STATE_HISTORY)
                    .expect("open chain_state_history");
                ch.remove(1u64).expect("remove chain_state_history[1]");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("missing rollback substrate must reject");
        let msg = format!("{err}");
        assert!(msg.contains("rollback substrate missing"), "msg={msg}",);
    }

    #[test]
    fn open_rejects_stored_root_diverging_from_tip_header() {
        // The integrity check the genesis seed displaced, restored as a
        // header anchor: an applied tip's stored root must equal the tip
        // header's committed `state_root`. Mutating `STATE_META[root_digest]`
        // to any other value — here the genesis digest, exactly the case a
        // bare "root == genesis ⇒ empty block" heuristic would wave through
        // — is a torn write the anchor now rejects at open.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            apply_synth(&mut store, 1); // header[1].state_root = synth_digest(1)
        }
        // Rewrite ONLY the stored root to the genesis seed; header[1] still
        // commits synth_digest(1), so root and header now disagree.
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "rewrite").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut meta = txn.open_table(crate::store::STATE_META).expect("open");
                meta.insert(ROOT_DIGEST_KEY, &TEST_GENESIS_DIGEST[..])
                    .expect("rewrite root to genesis seed");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("root diverging from the tip header's state_root must reject");
        let msg = format!("{err}");
        assert!(msg.contains("disagrees with tip header"), "msg={msg}");
    }

    #[test]
    fn open_accepts_applied_root_matching_tip_header() {
        // The legitimate empty-block shape: a height-1 block that changed
        // no boxes leaves the root at the genesis seed AND its header
        // commits that same genesis digest as `state_root`. Because the
        // stored root agrees with the header anchor, open accepts it — the
        // anchor rejects root/header divergence, never the genesis value
        // itself.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            // Empty block at height 1: header commits the genesis root and
            // the applied root stays at the genesis seed.
            let header_bytes = synth_header_bytes(1, TEST_GENESIS_DIGEST);
            HeaderSectionStore::store_header(&store, &synth_header_id(1), &header_bytes)
                .expect("store empty-block tip header");
            store
                .apply_block_digest(TEST_GENESIS_DIGEST, synth_chain_state(1), None)
                .expect("apply empty block at height 1");
        }
        let store =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect("applied root matching the tip header must be accepted");
        assert_eq!(store.height(), 1);
        assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
    }

    #[test]
    fn open_rejects_applied_store_with_wrong_genesis_digest() {
        // Cross-network mis-open guard: a committed store carries its
        // network's genesis digest in DIGEST_HISTORY[0]. Reopening it
        // with a DIFFERENT supplied genesis digest must fail loud at
        // open — not boot clean and only diverge at a deep rollback.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            // Seed + apply with the real mainnet genesis digest.
            let genesis = ergo_chain_spec::GenesisParams::mainnet().state_digest;
            let mut store =
                DigestStateStore::open(&db_path, scala_launch(), test_voting(), genesis)
                    .expect("open");
            for h in 1u32..=2 {
                apply_synth(&mut store, h);
            }
        }
        // Reopen with a foreign genesis digest (testnet's).
        let foreign = ergo_chain_spec::GenesisParams::testnet().state_digest;
        let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), foreign)
            .expect_err("wrong-network genesis digest must reject at open");
        let msg = format!("{err}");
        assert!(msg.contains("wrong-network or corrupted dir"), "msg={msg}");
    }

    #[test]
    fn fresh_open_rejects_cross_network_reopen_before_first_apply() {
        // A NEVER-APPLIED dir persists no genesis digest (the root lives
        // in memory until the first apply writes DIGEST_HISTORY[0]), so
        // the committed-store digest guard cannot fire here. The one row
        // the first fresh open DID persist is the genesis VOTED_PARAMS[0]
        // launch baseline. Reopening the same fresh dir for a different
        // network — distinct launch params — must reject, not silently
        // reuse the first network's protocol baseline against the second
        // network's genesis root.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");

        // Two distinct per-network launch baselines. `scala_launch()` is
        // network A; a single-field tweak stands in for network B's
        // distinct launch parameters (mainnet/testnet differ in real
        // cost tables, so the equality guard is a sound discriminator).
        let launch_a = scala_launch();
        let mut launch_b = scala_launch();
        launch_b.storage_fee_factor += 1;
        assert_ne!(launch_a, launch_b, "the two launches must differ");

        // First fresh open seeds VOTED_PARAMS[0] from launch A. No apply.
        {
            let store =
                DigestStateStore::open(&db_path, launch_a, test_voting(), TEST_GENESIS_DIGEST)
                    .expect("first fresh open seeds launch A");
            assert_eq!(store.height(), 0, "still fresh — never applied");
        }

        // Reopen the same fresh dir with network B's launch — must reject.
        let err = DigestStateStore::open(&db_path, launch_b, test_voting(), TEST_GENESIS_DIGEST)
            .expect_err("cross-network fresh reopen must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("different network"),
            "rejection must name the cross-network cause: {msg}",
        );

        // Reopening with the SAME launch (A) is fine — idempotent.
        DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
            .expect("same-network reopen of a fresh dir must succeed");
    }

    #[test]
    fn open_rejects_deep_history_hole_below_tip() {
        // A hole BELOW the immediate parent (h-1) — the case a
        // presence-only check on h-1 would miss. Apply to height 5,
        // punch out history[2], reopen. The density check must catch
        // it (len != last+1) so a deep reorg never hits a missing row
        // at runtime.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=5 {
                apply_synth(&mut store, h);
            }
        }
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
                dh.remove(2u64).expect("remove digest_history[2]");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("deep history hole must reject");
        let msg = format!("{err}");
        assert!(msg.contains("holes"), "msg={msg}");
    }

    #[test]
    fn open_rejects_chain_index_hole_below_tip() {
        // CHAIN_INDEX is a shared load-bearing height→block-id table.
        // A hole below the tip (the tip alone matches chain_state)
        // must be caught at open, not surface in a later point lookup
        // or reorg walk.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=5 {
                apply_synth(&mut store, h);
            }
        }
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut idx = txn
                    .open_table(crate::store::CHAIN_INDEX)
                    .expect("open chain_index");
                idx.remove(3u64).expect("punch hole at chain_index[3]");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("chain_index hole must reject");
        let msg = format!("{err}");
        assert!(msg.contains("chain_index not dense"), "msg={msg}");
    }

    #[test]
    fn applied_digest_dir_with_lost_sentinel_not_restampable_as_utxo() {
        // Defense-in-depth: if a digest-verifier dir loses its
        // `data_dir_state_type` sentinel to partial corruption, the
        // on-disk markers (history ledger / root_digest key) must
        // still prevent it from being silently re-stamped as the
        // UTXO backend.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            apply_synth(&mut store, 1);
        }
        // Delete only the sentinel key, leaving the digest data intact.
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut meta = txn
                    .open_table(crate::store::CHAIN_STATE_META)
                    .expect("open chain_state_meta");
                meta.remove(crate::store::DATA_DIR_STATE_TYPE_KEY)
                    .expect("remove sentinel");
            }
            txn.commit().expect("commit");
        }
        // Re-stamping as utxo must be refused — the digest markers
        // (history ledger / root_digest key) are still on disk. Test
        // the stamp guard directly rather than through StateStore::open
        // so we exercise the misopen logic, not StateStore's
        // reconstruction of a frankenstein dir.
        let db = crate::redb_util::open_with_repair_logging(&db_path, "reopen").expect("reopen");
        let err = crate::store::verify_or_init_state_type_inner(&db, "utxo")
            .expect_err("utxo re-stamp of a digest-verifier dir must reject");
        let msg = format!("{err}");
        assert!(msg.contains("digest-verifier"), "msg={msg}");
        assert!(msg.contains("utxo"), "msg={msg}");
    }

    #[test]
    fn frankenstore_with_both_schemas_and_no_sentinel_hard_fails() {
        // A dir carrying BOTH a UTXO arena row AND digest-verifier
        // markers, with no sentinel, is corrupt — the stamp guard
        // must refuse to infer either backend rather than silently
        // pick UTXO.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            apply_synth(&mut store, 1); // writes digest markers
        }
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                // Inject an AVL_NODES row (UTXO marker) and delete the
                // sentinel — now both schemas appear present.
                let mut avl = txn.open_table(crate::store::AVL_NODES).expect("open avl");
                avl.insert(0u64, &[0x01u8, 0x02][..])
                    .expect("inject avl row");
                let mut meta = txn
                    .open_table(crate::store::CHAIN_STATE_META)
                    .expect("open chain_state_meta");
                meta.remove(crate::store::DATA_DIR_STATE_TYPE_KEY)
                    .expect("remove sentinel");
            }
            txn.commit().expect("commit");
        }
        let db = crate::redb_util::open_with_repair_logging(&db_path, "reopen").expect("reopen");
        let err = crate::store::verify_or_init_state_type_inner(&db, "utxo")
            .expect_err("frankenstore must hard-fail");
        let msg = format!("{err}");
        assert!(msg.contains("incompatible schemas"), "msg={msg}");
    }

    #[test]
    fn rollback_rejects_history_row_with_wrong_height_in_body() {
        // A CHAIN_STATE_HISTORY row that decodes cleanly but encodes
        // the wrong height for its key must be caught at rollback
        // time, before its corrupt payload is written into
        // CHAIN_STATE_META.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=3 {
                apply_synth(&mut store, h);
            }
        }
        // Overwrite CHAIN_STATE_HISTORY[2] with a snapshot that
        // (wrongly) claims height 99.
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let bogus = ChainStateMeta {
                    best_header_id: synth_header_id(99),
                    best_header_height: 99,
                    best_header_score: vec![0x09],
                    best_full_block_id: synth_header_id(99),
                    best_full_block_height: 99,
                    header_availability: HeaderAvailability::Dense,
                };
                let mut ch = txn
                    .open_table(CHAIN_STATE_HISTORY)
                    .expect("open chain_state_history");
                ch.insert(2u64, bogus.serialize().as_slice())
                    .expect("overwrite history[2]");
            }
            txn.commit().expect("commit");
        }
        let mut store = open_at_path(&db_path);
        let err = store
            .rollback_to(2)
            .expect_err("rollback to a corrupt-body snapshot must reject");
        let msg = format!("{err}");
        assert!(msg.contains("body does not match its key"), "msg={msg}");
        // The store's in-memory state must be untouched by the
        // rejected rollback (validation happens before any mutation).
        assert_eq!(store.height(), 3);
    }

    #[test]
    fn rollback_rejects_history_row_with_id_disagreeing_with_chain_index() {
        // A CHAIN_STATE_HISTORY[target] row whose best_full_block_id
        // disagrees with CHAIN_INDEX[target] (the row that becomes
        // the post-rollback tip) must be caught before commit.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=3 {
                apply_synth(&mut store, h);
            }
        }
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                // Right height (2), wrong block id.
                let bogus = ChainStateMeta {
                    best_header_id: [0xDDu8; 32],
                    best_header_height: 2,
                    best_header_score: vec![0x02],
                    best_full_block_id: [0xDDu8; 32],
                    best_full_block_height: 2,
                    header_availability: HeaderAvailability::Dense,
                };
                let mut ch = txn
                    .open_table(CHAIN_STATE_HISTORY)
                    .expect("open chain_state_history");
                ch.insert(2u64, bogus.serialize().as_slice())
                    .expect("overwrite history[2]");
            }
            txn.commit().expect("commit");
        }
        let mut store = open_at_path(&db_path);
        let err = store
            .rollback_to(2)
            .expect_err("id/chain_index disagreement must reject");
        let msg = format!("{err}");
        assert!(msg.contains("disagrees with chain_index"), "msg={msg}");
        assert_eq!(store.height(), 3);
    }

    #[test]
    fn open_rejects_applied_store_missing_genesis_voted_params() {
        // An applied store that lost VOTED_PARAMS[0] must fail loud,
        // NOT silently re-seed — a missing genesis row would let
        // read_latest_at fall back to a later epoch's parameters.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=2 {
                apply_synth(&mut store, h);
            }
        }
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut vp = txn
                    .open_table(crate::active_params::VOTED_PARAMS)
                    .expect("open voted_params");
                vp.remove(0u64).expect("remove voted_params[0]");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("missing genesis voted_params on applied store must reject");
        let msg = format!("{err}");
        assert!(msg.contains("genesis voted-params row absent"), "msg={msg}",);
    }

    #[test]
    fn divergent_header_and_full_block_pointers_round_trip() {
        // ChainStateMeta carries best_header_* SEPARATE from
        // best_full_block_*, plus a HeaderAvailability tag. The
        // persistence path must round-trip all of them — the synth
        // helper pins both pointers to the same id, so this test
        // exercises the divergent + PoPowSparse shape explicitly.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        let divergent = ChainStateMeta {
            best_header_id: [0xA1u8; 32],
            best_header_height: 9,
            best_header_score: vec![0x07, 0x42],
            best_full_block_id: [0xB2u8; 32],
            best_full_block_height: 1,
            header_availability: HeaderAvailability::PoPowSparse {
                dense_from_height: 4,
                proof_suffix_height: 9,
            },
        };
        {
            let mut store = open_at_path(&db_path);
            apply_digest_with_header(&mut store, synth_digest(1), divergent, None);
        }
        let store = open_at_path(&db_path);
        let cs = store.chain_state();
        assert_eq!(cs.best_header_id, [0xA1u8; 32]);
        assert_eq!(cs.best_header_height, 9);
        assert_eq!(cs.best_header_score, vec![0x07, 0x42]);
        assert_eq!(cs.best_full_block_id, [0xB2u8; 32]);
        assert_eq!(cs.best_full_block_height, 1);
        assert_eq!(
            cs.header_availability,
            HeaderAvailability::PoPowSparse {
                dense_from_height: 4,
                proof_suffix_height: 9,
            },
        );
    }

    // ----- oracle parity (state-type stamp shared with StateStore) -----

    #[test]
    fn reopening_a_utxo_stamped_dir_as_digest_verifier_is_rejected() {
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("state.redb");
        {
            let store = crate::store::StateStore::open(&db_path).expect("StateStore::open");
            store.verify_or_init_state_type("utxo").expect("stamp utxo");
            drop(store);
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("digest-verifier open of utxo dir must reject");
        let msg = format!("{err}");
        assert!(msg.contains("state_type"), "msg={msg}");
        assert!(
            msg.contains("digest-verifier") && msg.contains("utxo"),
            "rejection must name both backends: {msg}",
        );
    }

    #[test]
    fn reopening_a_mode_6_digest_dir_as_digest_verifier_is_rejected() {
        // The collision Codex flagged: a Mode 6 dir stamps "digest"
        // (StateStore headers-only schema). Mode 5's DigestStateStore
        // stamps "digest-verifier" (a distinct, incompatible schema).
        // Opening a Mode 6 dir as Mode 5 must REJECT — otherwise the
        // digest chain would silently boot against an empty
        // StateStore-shaped dir.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("state.redb");
        {
            let store = crate::store::StateStore::open(&db_path).expect("StateStore::open");
            store
                .verify_or_init_state_type("digest")
                .expect("stamp digest (Mode 6)");
            drop(store);
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("Mode 6 digest dir opened as Mode 5 must reject");
        let msg = format!("{err}");
        assert!(msg.contains("state_type"), "msg={msg}");
        assert!(
            msg.contains("digest-verifier") && msg.contains("\"digest\""),
            "rejection must distinguish digest vs digest-verifier: {msg}",
        );
    }

    // ----- atomic-commit invariant -----

    #[test]
    fn apply_co_commits_voted_params_row() {
        // A co-committed row must land at a real epoch boundary
        // (height 2 under the test cadence of 2) and be keyed to that
        // height. Apply height 1 (no row), then the boundary block at
        // height 2 with `epoch_start_height = 2`.
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        apply_synth(&mut store, 1);
        let mut params = scala_launch();
        params.epoch_start_height = 2;
        apply_digest_with_header(
            &mut store,
            synth_digest(2),
            synth_chain_state(2),
            Some(params),
        );
        drop(store);
        let reopened = open_at(tmp.path());
        assert_eq!(reopened.height(), 2);
        assert_eq!(reopened.root_digest(), synth_digest(2));
        let read = reopened.db.begin_read().expect("begin_read");
        let table = read
            .open_table(crate::active_params::VOTED_PARAMS)
            .expect("open voted_params");
        let row = table.get(2u64).expect("get").expect("row present");
        assert!(
            !row.value().is_empty(),
            "voted_params row must be non-empty"
        );
    }

    #[test]
    fn apply_rejects_voted_params_at_non_epoch_boundary() {
        // A voted-params row at a non-epoch-start height (1 is not a
        // multiple of the test cadence 2) is a caller bug — reject it
        // before persisting, matching the Mode 1 guard.
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        let mut params = scala_launch();
        params.epoch_start_height = 1;
        let err = store
            .apply_block_digest(synth_digest(1), synth_chain_state(1), Some(params))
            .expect_err("voted_params at non-boundary height must reject");
        let msg = format!("{err}");
        assert!(msg.contains("non-epoch-start height"), "msg={msg}");
        assert_eq!(store.height(), 0);
    }

    #[test]
    fn apply_rejects_voted_params_row_keyed_to_wrong_height() {
        // At a real boundary (height 2), a row whose
        // epoch_start_height is not that height is a caller bug that
        // would persist consensus drift — reject it.
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        apply_synth(&mut store, 1);
        let mut params = scala_launch();
        params.epoch_start_height = 1024; // applying boundary height 2
        let err = store
            .apply_block_digest(synth_digest(2), synth_chain_state(2), Some(params))
            .expect_err("epoch_start_height != block height must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("epoch_start_height != block height"),
            "msg={msg}",
        );
        // The rejected apply must not have advanced the store past 1.
        assert_eq!(store.height(), 1);
    }

    #[test]
    fn rollback_prunes_voted_params_rows_above_target() {
        // Epoch-boundary reorg invariant: params rows above the
        // rollback target must not survive. Boundary blocks at
        // heights 2 and 4 (test cadence 2) each co-commit a row;
        // odd heights carry none. Rolling back to height 1 must
        // prune the rows at 2 and 4.
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        for h in 1u32..=4 {
            let voted = if h.is_multiple_of(2) {
                let mut params = scala_launch();
                params.epoch_start_height = h;
                Some(params)
            } else {
                None
            };
            apply_digest_with_header(&mut store, synth_digest(h), synth_chain_state(h), voted);
        }
        // Pre-rollback: boundary rows at 2 and 4 are present.
        {
            let read = store.db.begin_read().expect("begin_read");
            let t = read
                .open_table(crate::active_params::VOTED_PARAMS)
                .expect("open");
            assert!(t.get(2u64).expect("get").is_some());
            assert!(t.get(4u64).expect("get").is_some());
        }
        store.rollback_to(1).expect("rollback");
        // After rollback to height 1: rows above 1 must be pruned.
        let read = store.db.begin_read().expect("begin_read");
        let t = read
            .open_table(crate::active_params::VOTED_PARAMS)
            .expect("open");
        assert!(
            t.get(2u64).expect("get").is_none(),
            "row at height 2 must be pruned (2 > target=1)",
        );
        assert!(
            t.get(4u64).expect("get").is_none(),
            "row at height 4 must be pruned",
        );
        // Genesis (0) survives.
        assert!(
            t.get(0u64).expect("get").is_some(),
            "genesis voted_params row must survive rollback",
        );
    }

    #[test]
    fn open_rejects_orphan_history_with_no_chain_state() {
        // A torn write that lost chain_state / root / chain_index but
        // left orphan history rows must NOT be classified fresh —
        // booting as genesis would silently discard an applied chain.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=2 {
                apply_synth(&mut store, h);
            }
        }
        // Wipe the authoritative anchors but leave the history
        // ledgers intact.
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut meta = txn.open_table(crate::store::STATE_META).expect("open");
                meta.remove(ROOT_DIGEST_KEY).expect("remove root_digest");
                let mut cs = txn
                    .open_table(crate::store::CHAIN_STATE_META)
                    .expect("open chain_state_meta");
                cs.remove(CHAIN_STATE_KEY).expect("remove chain_state");
                let mut idx = txn
                    .open_table(crate::store::CHAIN_INDEX)
                    .expect("open chain_index");
                let keys: Vec<u64> = idx
                    .iter()
                    .expect("iter")
                    .filter_map(|r| r.ok().map(|(k, _)| k.value()))
                    .collect();
                for k in keys {
                    idx.remove(k).expect("remove chain_index row");
                }
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("orphan history must reject, not boot fresh");
        let msg = format!("{err}");
        assert!(msg.contains("history_rows=true"), "msg={msg}");
    }

    #[test]
    fn open_rejects_corrupt_genesis_history_root() {
        // digest_history[0] must hold the network's genesis digest. If
        // it is corrupted to any other value, the open-time
        // cross-network guard rejects it before the store is ever
        // handed out — the corrupt genesis substrate can no longer
        // reach a rollback_to(0) at runtime.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=2 {
                apply_synth(&mut store, h);
            }
        }
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
                dh.insert(0u64, &synth_digest(7)[..])
                    .expect("corrupt history[0]");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("corrupt genesis history row must reject at open");
        let msg = format!("{err}");
        assert!(msg.contains("wrong-network or corrupted dir"), "msg={msg}");
    }

    #[test]
    fn rollback_to_applied_empty_block_height_with_genesis_root_succeeds() {
        // The empty-block shape: block 1 changed no boxes, so the root at
        // height 1 equals the genesis digest AND header[1] commits that
        // same digest. Rolling back FROM a later tip TO that height must
        // succeed — the restored root agrees with the tip header anchor.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        let mut store = open_at_path(&db_path);
        // Height 1: an empty block whose header commits the genesis root,
        // leaving the applied root at the genesis seed.
        let header_bytes = synth_header_bytes(1, TEST_GENESIS_DIGEST);
        HeaderSectionStore::store_header(&store, &synth_header_id(1), &header_bytes)
            .expect("store empty-block tip header");
        store
            .apply_block_digest(TEST_GENESIS_DIGEST, synth_chain_state(1), None)
            .expect("apply empty block at height 1");
        // Heights 2..=3: normal applies that advance the root.
        for h in 2u32..=3 {
            apply_synth(&mut store, h);
        }
        // Roll back to the empty-block height. digest_history[1] holds the
        // genesis digest and header[1] commits it; this must restore
        // cleanly, not reject.
        store
            .rollback_to(1)
            .expect("rollback to an applied empty-block height must succeed");
        assert_eq!(store.height(), 1);
        assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
        assert_eq!(store.chain_state().best_full_block_id, synth_header_id(1));
    }

    #[test]
    fn rollback_to_rejects_restored_root_diverging_from_tip_header() {
        // Symmetric to the open-path anchor: if `DIGEST_HISTORY[target]`
        // is mutated so the restored root no longer matches the target
        // tip header's `state_root`, rollback must refuse to install it
        // live — the same poisoned root open would have rejected.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=3 {
                apply_synth(&mut store, h);
            }
        }
        // Corrupt the height-1 snapshot root to the genesis seed; header[1]
        // still commits synth_digest(1), so a rollback to 1 must reject.
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
                dh.insert(1u64, &TEST_GENESIS_DIGEST[..])
                    .expect("corrupt digest_history[1]");
            }
            txn.commit().expect("commit");
        }
        // Reopen succeeds: the TIP (height 3) root + header still agree.
        let mut store =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect("reopen at an intact tip");
        let err = store
            .rollback_to(1)
            .expect_err("restored root diverging from the tip header must reject");
        let msg = format!("{err}");
        assert!(msg.contains("disagrees with tip header"), "msg={msg}");
    }

    #[test]
    fn open_rejects_applied_tip_with_missing_header() {
        // An applied tip cannot exist without its header — the full block
        // is verified against that header before it commits. A height-1
        // store whose tip header row is absent is therefore corruption,
        // not a benign miss; open must reject it rather than boot a tip it
        // cannot anchor.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            // Apply height 1 through the raw seam WITHOUT storing the tip
            // header, fabricating the absent-header shape.
            store
                .apply_block_digest(synth_digest(1), synth_chain_state(1), None)
                .expect("apply h1 without a tip header");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("applied tip with no stored header must reject at open");
        let msg = format!("{err}");
        assert!(msg.contains("no stored header"), "msg={msg}");
    }

    #[test]
    fn rollback_to_rejects_target_tip_with_missing_header() {
        // The rollback anchor needs the target tip's header to reconcile
        // the restored root. If height 1's header is absent, rolling back
        // to it must reject — the same absent-header corruption the open
        // path catches, surfaced at the reorg seam instead.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        let mut store = open_at_path(&db_path);
        // Height 1 through the raw seam, no header stored.
        store
            .apply_block_digest(synth_digest(1), synth_chain_state(1), None)
            .expect("apply h1 without a tip header");
        // Heights 2..=3 with headers, so the live tip is anchorable and the
        // rollback's other cross-checks pass before it reaches the anchor.
        for h in 2u32..=3 {
            apply_synth(&mut store, h);
        }
        let err = store
            .rollback_to(1)
            .expect_err("rollback to a target whose tip header is absent must reject");
        let msg = format!("{err}");
        assert!(msg.contains("no stored header"), "msg={msg}");
    }

    #[test]
    fn lost_sentinel_with_only_chain_state_history_still_detected_as_digest_verifier() {
        // R8-2: the marker check must treat CHAIN_STATE_HISTORY as a
        // digest-verifier marker too. A torn write that loses the
        // sentinel, DIGEST_HISTORY, and root_digest but keeps
        // CHAIN_STATE_HISTORY must still NOT be re-stampable as utxo.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            apply_synth(&mut store, 1);
        }
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                // Strip sentinel, DIGEST_HISTORY, and root_digest;
                // leave CHAIN_STATE_HISTORY as the sole marker.
                let mut cs = txn
                    .open_table(crate::store::CHAIN_STATE_META)
                    .expect("open chain_state_meta");
                cs.remove(crate::store::DATA_DIR_STATE_TYPE_KEY)
                    .expect("remove sentinel");
                let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
                let keys: Vec<u64> = dh
                    .iter()
                    .expect("iter")
                    .filter_map(|r| r.ok().map(|(k, _)| k.value()))
                    .collect();
                for k in keys {
                    dh.remove(k).expect("remove digest_history row");
                }
                let mut meta = txn.open_table(crate::store::STATE_META).expect("open");
                meta.remove(ROOT_DIGEST_KEY).expect("remove root_digest");
            }
            txn.commit().expect("commit");
        }
        let db = crate::redb_util::open_with_repair_logging(&db_path, "reopen").expect("reopen");
        let err = crate::store::verify_or_init_state_type_inner(&db, "utxo")
            .expect_err("CHAIN_STATE_HISTORY alone must still block utxo re-stamp");
        let msg = format!("{err}");
        assert!(msg.contains("digest-verifier"), "msg={msg}");
        assert!(msg.contains("utxo"), "msg={msg}");
    }

    #[test]
    fn apply_rejects_chain_state_with_header_behind_full_block() {
        // best_header_height must lead or equal best_full_block_height.
        // A chain state with the header tip behind the full-block tip
        // is a nonsense fork-choice view — reject at the seam.
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        let bad = ChainStateMeta {
            best_header_id: synth_header_id(1),
            best_header_height: 0, // behind best_full_block_height = 1
            best_header_score: vec![0x01],
            best_full_block_id: synth_header_id(1),
            best_full_block_height: 1,
            header_availability: HeaderAvailability::Dense,
        };
        let err = store
            .apply_block_digest(synth_digest(1), bad, None)
            .expect_err("header behind full block must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("best_header_height < best_full_block_height"),
            "msg={msg}",
        );
        assert_eq!(store.height(), 0);
    }

    #[test]
    fn open_rejects_orphan_voted_params_row_above_tip() {
        // A voted-params row above the committed tip (here, on a
        // fresh store whose tip is 0) is an orphan from a torn write
        // — reject at open rather than let read_latest_at key off it.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        // First open seeds VOTED_PARAMS[0]; store stays fresh (no apply).
        drop(open_at_path(&db_path));
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut vp = txn
                    .open_table(crate::active_params::VOTED_PARAMS)
                    .expect("open voted_params");
                // Inject a row at height 5 — no chain has been applied.
                let mut p = scala_launch();
                p.epoch_start_height = 5;
                vp.insert(5u64, p.serialize().expect("serialize").as_slice())
                    .expect("inject orphan row");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("orphan voted_params row above tip must reject");
        let msg = format!("{err}");
        assert!(msg.contains("not a valid epoch boundary"), "msg={msg}");
    }

    #[test]
    fn open_rejects_off_boundary_voted_params_row() {
        // A voted-params row at a non-epoch-boundary height (3 is not
        // a multiple of the test cadence 2) is off-boundary garbage.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=4 {
                apply_synth(&mut store, h);
            }
        }
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut vp = txn
                    .open_table(crate::active_params::VOTED_PARAMS)
                    .expect("open voted_params");
                let mut p = scala_launch();
                p.epoch_start_height = 3; // 3 % 2 != 0
                vp.insert(3u64, p.serialize().expect("serialize").as_slice())
                    .expect("inject off-boundary row");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("off-boundary voted_params row must reject");
        let msg = format!("{err}");
        assert!(msg.contains("not a valid epoch boundary"), "msg={msg}");
    }

    #[test]
    fn failed_misopen_does_not_poison_state_type_sentinel() {
        // A sentinel-less dir carrying a StateStore-shaped
        // chain_state (no root_digest, no digest history) opened as
        // Mode 5 must fail at shape validation WITHOUT writing the
        // `data_dir_state_type` sentinel — otherwise the mis-open
        // would re-classify the dir as digest-verifier on disk.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            // Write only a genesis chain_state row — no sentinel, no
            // root_digest, no history ledgers (a torn / foreign shape).
            let db = crate::redb_util::open_with_repair_logging(&db_path, "seed").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut cs = txn
                    .open_table(crate::store::CHAIN_STATE_META)
                    .expect("open chain_state_meta");
                cs.insert(
                    CHAIN_STATE_KEY,
                    genesis_chain_state().serialize().as_slice(),
                )
                .expect("write chain_state");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("shape-invalid dir must reject");
        // It fails on shape validation, not state-type mismatch.
        let msg = format!("{err}");
        assert!(msg.contains("root_digest absent"), "msg={msg}");
        // Critical: the sentinel must NOT have been written by the
        // failed open.
        let db = crate::redb_util::open_with_repair_logging(&db_path, "verify").expect("reopen");
        let read = db.begin_read().expect("begin_read");
        let table = read
            .open_table(crate::store::CHAIN_STATE_META)
            .expect("open chain_state_meta");
        let sentinel = table
            .get(crate::store::DATA_DIR_STATE_TYPE_KEY)
            .expect("get sentinel");
        assert!(
            sentinel.is_none(),
            "failed mis-open must not stamp the data_dir_state_type sentinel",
        );
    }

    #[test]
    fn open_rejects_voted_params_row_with_bad_payload_at_valid_key() {
        // A row at a valid boundary key but whose bytes decode to a
        // different embedded epoch_start_height is corruption — open
        // must reject it, not defer to a lazy read_latest_at failure.
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            for h in 1u32..=4 {
                apply_synth(&mut store, h);
            }
        }
        {
            let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
            let txn = crate::begin_write_qr(&db).expect("begin_write");
            {
                let mut vp = txn
                    .open_table(crate::active_params::VOTED_PARAMS)
                    .expect("open voted_params");
                // Valid boundary key 2, but the body claims height 4.
                let mut p = scala_launch();
                p.epoch_start_height = 4;
                vp.insert(2u64, p.serialize().expect("serialize").as_slice())
                    .expect("inject mismatched-body row");
            }
            txn.commit().expect("commit");
        }
        let err =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
                .expect_err("mismatched-body voted_params row must reject");
        let msg = format!("{err}");
        assert!(msg.contains("embedded epoch_start_height"), "msg={msg}",);
    }

    // ----- StateBackend read-side traits -----

    #[test]
    fn header_section_store_round_trips_a_header_through_the_trait() {
        let tmp = tempdir().expect("tempdir");
        let store = open_at(tmp.path());
        let id = synth_header_id(42);
        // `store_header` attempts to parse the bytes for the section
        // height index but swallows parse failures, so opaque bytes
        // round-trip cleanly — this test exercises the store/get path,
        // not header parsing.
        let bytes = vec![0xABu8; 64];
        HeaderSectionStore::store_header(&store, &id, &bytes).expect("store_header");
        let got = HeaderSectionStore::get_header(&store, &id).expect("get_header");
        assert_eq!(got, Some(bytes));
        // An unknown id reads back as absent.
        assert_eq!(
            HeaderSectionStore::get_header(&store, &synth_header_id(99)).expect("get_header"),
            None,
        );
    }

    #[test]
    fn chain_state_read_reports_genesis_on_fresh_store() {
        let tmp = tempdir().expect("tempdir");
        let store = open_at(tmp.path());
        assert_eq!(ChainStateRead::height(&store), 0);
        // `ChainStateMeta` has no `PartialEq`; compare the load-bearing
        // pointers field-by-field, matching the snapshot the inherent
        // `chain_state()` accessor exposes.
        let snapshot = ChainStateRead::chain_state_meta(&store);
        let inherent = store.chain_state();
        assert_eq!(snapshot.best_header_id, inherent.best_header_id);
        assert_eq!(snapshot.best_header_height, inherent.best_header_height);
        assert_eq!(snapshot.best_header_score, inherent.best_header_score);
        assert_eq!(snapshot.best_full_block_id, inherent.best_full_block_id);
        assert_eq!(
            snapshot.best_full_block_height,
            inherent.best_full_block_height,
        );
        assert_eq!(snapshot.header_availability, inherent.header_availability);
        assert_eq!(
            ChainStateRead::read_minimal_full_block_height(&store).expect("min full block"),
            1,
        );
        // The genesis launch row keys to height 0.
        assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 0);
    }

    #[test]
    fn session_invalid_round_trips_through_the_trait() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        let id = synth_header_id(7);
        assert!(
            !HeaderSectionStore::is_invalid(&store, &id).expect("is_invalid"),
            "unknown id starts valid",
        );
        HeaderSectionStore::mark_session_invalid(&mut store, id);
        assert!(
            HeaderSectionStore::is_invalid(&store, &id).expect("is_invalid"),
            "marked id reads invalid",
        );
        assert!(
            !HeaderSectionStore::is_invalid(&store, &synth_header_id(8)).expect("is_invalid"),
            "an unmarked id stays valid",
        );
    }

    #[test]
    fn apply_across_epoch_boundary_refreshes_cached_active_params() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        // Genesis: caches reflect the launch row.
        assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 0);
        let launch_input_cost = scala_launch().input_cost;
        assert_eq!(
            ChainStateRead::active_params(&store).input_cost,
            launch_input_cost,
        );

        apply_synth(&mut store, 1); // non-boundary, no row

        // Epoch boundary (voting_length = 2): co-commit a changed-param row.
        let mut row = scala_launch();
        row.epoch_start_height = 2;
        row.input_cost = 9999;
        store
            .apply_block_digest(synth_digest(2), synth_chain_state(2), Some(row))
            .expect("apply h2 with epoch-boundary row");

        // The read-side cache tracks the committed tip, not the open snapshot.
        assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 2);
        assert_eq!(ChainStateRead::active_params(&store).input_cost, 9999);
        // validation_settings stays consistent with a fresh fold at the tip.
        let fresh = crate::active_params::compute_validation_settings_at(
            &store.db.begin_read().expect("begin_read"),
            store.height(),
        )
        .expect("fold");
        assert_eq!(ChainStateRead::validation_settings(&store), &fresh);
    }

    #[test]
    fn rollback_across_epoch_boundary_reverts_cached_active_params() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        apply_synth(&mut store, 1);
        let mut row = scala_launch();
        row.epoch_start_height = 2;
        row.input_cost = 9999;
        store
            .apply_block_digest(synth_digest(2), synth_chain_state(2), Some(row))
            .expect("apply h2");
        assert_eq!(ChainStateRead::active_params(&store).input_cost, 9999);

        store.rollback_to(1).expect("rollback to 1");
        // The epoch row above height 1 was pruned, so the cache reverts
        // to the launch set rather than reporting the rolled-back epoch.
        assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 0);
        assert_eq!(
            ChainStateRead::active_params(&store).input_cost,
            scala_launch().input_cost,
        );
    }

    #[test]
    fn reopen_after_epoch_apply_reads_tip_params_not_genesis() {
        let tmp = tempdir().expect("tempdir");
        let db_path = tmp.path().join("digest_state.redb");
        {
            let mut store = open_at_path(&db_path);
            apply_synth(&mut store, 1);
            let mut row = scala_launch();
            row.epoch_start_height = 2;
            row.input_cost = 9999;
            apply_digest_with_header(&mut store, synth_digest(2), synth_chain_state(2), Some(row));
        }
        // Reopen at a non-genesis tip: open() must fold params from the
        // persisted voted_params rows, not reset to launch/empty.
        let store = open_at_path(&db_path);
        assert_eq!(store.height(), 2);
        assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 2);
        assert_eq!(ChainStateRead::active_params(&store).input_cost, 9999);
    }

    /// Phase C-2 — the `BlockApply` apply-bridge.
    ///
    /// The successful real-box-change path (a header's `state_root`
    /// advancing across genuine inserts/removes, verified against a
    /// Scala/mainnet ADProof) is the consensus gate and is covered by
    /// the Phase 5.7 corpus replay, NOT here — a self-generated proof
    /// is not a valid consensus oracle. These tests cover the bridge's
    /// guard logic, error classification, session-invalid marking, and
    /// the commit plumbing using a no-op transition (which still
    /// exercises section fetch → parse → verifier construction at a
    /// real AVL root → finalize → `apply_block_digest`, independent of
    /// genesis `state_root` semantics).
    mod c2_bridge {
        use super::*;
        use crate::backend::BlockApply;
        use crate::chain::{ChainStateMeta, HeaderAvailability};
        use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
        use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
        use ergo_avltree_rust::batch_node::{AVLTree, Node, NodeHeader};
        use ergo_avltree_rust::operation::{KeyValue, Operation};
        use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
        use ergo_primitives::group_element::GroupElement;
        use ergo_primitives::writer::VlqWriter;
        use ergo_ser::ad_proofs::{write_ad_proofs, ADProofs};
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::header::{serialize_header, Header};
        use ergo_ser::modifier_id::{compute_section_id, TYPE_AD_PROOFS};
        use ergo_validation::block::CheckedBlock;
        use ergo_validation::header::CheckedHeader;
        use std::collections::{BTreeMap, BTreeSet};

        // ----- helpers -----

        fn new_prover() -> BatchAVLProver {
            let tree = AVLTree::new(
                |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
                32,
                None,
            );
            BatchAVLProver::new(tree, true)
        }

        fn prover_digest(p: &mut BatchAVLProver) -> [u8; 33] {
            let raw = p.digest().expect("prover has a digest");
            let mut out = [0u8; 33];
            out.copy_from_slice(&raw);
            out
        }

        /// A committed non-empty prover root R0 plus a proof of ZERO
        /// operations at R0. Driving the verifier with no box changes
        /// against this proof finalizes back to R0 — the minimal valid
        /// transition that still flexes the whole bridge.
        fn committed_root_and_noop_proof() -> ([u8; 33], Vec<u8>) {
            let mut p = new_prover();
            p.perform_one_operation(&Operation::Insert(KeyValue {
                key: bytes::Bytes::from(vec![7u8; 32]),
                value: bytes::Bytes::from(vec![9u8; 16]),
            }))
            .expect("seed insert");
            let _ = p.generate_proof(); // commit the insert; tree now at R0
            let r0 = prover_digest(&mut p);
            let noop_proof = p.generate_proof().to_vec(); // zero ops since commit
            (r0, noop_proof)
        }

        fn synth_block_header(
            height: u32,
            parent_id: [u8; 32],
            state_root: [u8; 33],
            ad_proofs_root: [u8; 32],
        ) -> Header {
            Header {
                version: 2,
                parent_id: ModifierId::from_bytes(parent_id),
                ad_proofs_root: Digest32::from_bytes(ad_proofs_root),
                state_root: ADDigest::from_bytes(state_root),
                transactions_root: Digest32::from_bytes([0u8; 32]),
                timestamp: 1_700_000_000,
                n_bits: 0x1d00ffff,
                height,
                extension_root: Digest32::from_bytes([0u8; 32]),
                votes: [0u8; 3],
                unparsed_bytes: vec![],
                solution: AutolykosSolution::V2 {
                    pk: GroupElement::from_bytes([0x02; 33]),
                    nonce: [0xAA; 8],
                },
            }
        }

        /// Canonical header id + an empty-transaction `CheckedBlock`.
        fn empty_block(header: Header) -> ([u8; 32], CheckedBlock) {
            let (_, id_modifier) = serialize_header(&header).expect("serialize_header");
            let header_id = *id_modifier.as_bytes();
            let checked = CheckedHeader::trust_me(header, header_id);
            (header_id, CheckedBlock::from_parts(checked, vec![]))
        }

        fn section_bytes(inner_header_id: [u8; 32], proof_bytes: Vec<u8>) -> Vec<u8> {
            let ap = ADProofs {
                header_id: ModifierId::from_bytes(inner_header_id),
                proof_bytes,
            };
            let mut w = VlqWriter::new();
            write_ad_proofs(&mut w, &ap);
            w.result()
        }

        fn section_id(header_id: [u8; 32], ad_proofs_root: [u8; 32]) -> [u8; 32] {
            compute_section_id(TYPE_AD_PROOFS, &header_id, &ad_proofs_root)
        }

        /// Seed an opened store to a committed non-genesis tip: root +
        /// `best_full_block_height = h`, with `best_header` one ahead so
        /// a linear apply at `h + 1` satisfies the chain-state
        /// invariant (header accepted before its full block).
        fn seed_tip(store: &mut DigestStateStore, root: [u8; 33], h: u32) {
            store.root_digest = root;
            let id = synth_header_id(h);
            store.chain_state = ChainStateMeta {
                best_header_id: id,
                best_header_height: h + 1,
                best_header_score: ((h as u64) + 1).to_be_bytes().to_vec(),
                best_full_block_id: id,
                best_full_block_height: h,
                header_availability: HeaderAvailability::Dense,
            };
        }

        struct NoopHook;
        impl crate::wallet::WalletApplyHook for NoopHook {
            fn tracked_p2pk_trees(&self) -> BTreeSet<Vec<u8>> {
                BTreeSet::new()
            }
            fn cached_pubkeys(&self) -> BTreeMap<u64, [u8; 33]> {
                BTreeMap::new()
            }
        }

        struct NoopGuard;
        impl crate::wallet::apply::RescanGuard for NoopGuard {
            fn abort_in_progress(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
                Ok(())
            }
            fn force_invalidate(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
                Ok(())
            }
        }

        // ----- happy path (no-op transition: commit plumbing) -----

        #[test]
        fn apply_full_block_noop_advances_full_block_tip() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path());
            let (r0, noop_proof) = committed_root_and_noop_proof();
            seed_tip(&mut store, r0, 4); // committed tip at height 4, root R0

            let ad_root = *blake2b256(&noop_proof).as_bytes();
            let header = synth_block_header(5, synth_header_id(4), r0, ad_root);
            let (header_id, block) = empty_block(header);
            store
                .headers
                .store_block_section_typed(
                    &section_id(header_id, ad_root),
                    &section_bytes(header_id, noop_proof),
                    TYPE_AD_PROOFS,
                )
                .expect("store ADProofs section");

            BlockApply::apply_full_block(&mut store, &block, None, None).expect("apply_full_block");

            // A no-op transition keeps the root; only the full-block tip
            // advances. A successful return means apply_block_digest
            // committed (it only mutates in-memory state post-commit).
            assert_eq!(store.root_digest(), r0);
            assert_eq!(store.height(), 5);
            assert_eq!(store.chain_state().best_full_block_id, header_id);
        }

        // ----- error paths -----

        #[test]
        fn apply_full_block_rejects_wallet_hook() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path());
            let header = synth_block_header(1, [0u8; 32], [0u8; 33], [0u8; 32]);
            let (_, block) = empty_block(header);
            let hook = NoopHook;
            let err = BlockApply::apply_full_block(&mut store, &block, None, Some(&hook))
                .expect_err("wallet hook must be rejected");
            assert!(
                matches!(err, StateError::InvalidPrecondition { .. }),
                "got {err:?}"
            );
            assert_eq!(store.height(), 0, "no state advance on rejection");
        }

        #[test]
        fn rollback_rejects_wallet_hook_and_rescan_guard() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path());
            let hook = NoopHook;
            let guard = NoopGuard;
            assert!(matches!(
                BlockApply::rollback_to(&mut store, 0, Some(&hook), None).expect_err("hook"),
                StateError::InvalidPrecondition { .. }
            ));
            assert!(matches!(
                BlockApply::rollback_to(&mut store, 0, None, Some(&guard)).expect_err("guard"),
                StateError::InvalidPrecondition { .. }
            ));
        }

        #[test]
        fn apply_full_block_wrong_height_is_out_of_order() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path()); // tip at genesis height 0
                                                 // Height 5 against a height-0 tip (parent is the genesis
                                                 // sentinel, matching the tip), rejected at the linear height
                                                 // preflight before any section/proof work.
            let header = synth_block_header(5, [0u8; 32], [0u8; 33], [0u8; 32]);
            let (_, block) = empty_block(header);
            let err = BlockApply::apply_full_block(&mut store, &block, None, None)
                .expect_err("out-of-order height must be rejected");
            assert!(
                matches!(
                    err,
                    StateError::ApplyOutOfOrder {
                        expected_next: 1,
                        got: 5
                    }
                ),
                "got {err:?}"
            );
            assert_eq!(store.height(), 0);
        }

        #[test]
        fn apply_full_block_non_tip_parent_is_non_linear_not_invalid() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path());
            seed_tip(&mut store, [1u8; 33], 4); // committed tip id = synth_header_id(4)
                                                // Correct height (5 == tip 4 + 1) but a parent that is NOT
                                                // the committed tip → not linearly applicable. Must reject
                                                // before proof work, and must NOT mark the block invalid (it
                                                // may be a valid fork block we simply cannot apply linearly).
            let foreign_parent = synth_header_id(99);
            let header = synth_block_header(5, foreign_parent, [1u8; 33], [0xCDu8; 32]);
            let (header_id, block) = empty_block(header);
            let err = BlockApply::apply_full_block(&mut store, &block, None, None)
                .expect_err("non-tip parent must be rejected");
            assert!(
                matches!(err, StateError::DigestNonLinearParent { height: 5, .. }),
                "got {err:?}"
            );
            assert!(
                !store.session_invalids.contains(&header_id),
                "a non-tip-parent block must not be marked session-invalid"
            );
            assert_eq!(store.height(), 4, "no state advance");
        }

        #[test]
        fn apply_full_block_genesis_parent_passes_linear_gate() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path()); // genesis: height 0
            let genesis_tip = store.chain_state().best_full_block_id;
            // A height-1 block whose parent IS the genesis tip passes
            // BOTH linear preflights (0 + 1 == 1, parent == tip) and
            // proceeds to section fetch — proving the gate ADMITS the
            // genesis transition rather than rejecting it as
            // out-of-order or non-linear. (The successful genesis apply
            // itself, seeding the verifier at the pinned genesis state
            // digest, is Phase 5.7's real-corpus territory.)
            let header = synth_block_header(1, genesis_tip, [1u8; 33], [0xCDu8; 32]);
            let (_, block) = empty_block(header);
            let err = BlockApply::apply_full_block(&mut store, &block, None, None)
                .expect_err("missing section");
            assert!(
                matches!(err, StateError::DigestAdProofsSectionMissing { .. }),
                "genesis-parent block must clear the linear gate, got {err:?}"
            );
        }

        #[test]
        fn apply_full_block_missing_section_is_unavailable_not_invalid() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path());
            seed_tip(&mut store, [1u8; 33], 4);
            let header = synth_block_header(5, synth_header_id(4), [1u8; 33], [0xCDu8; 32]);
            let (header_id, block) = empty_block(header);
            // No section stored.
            let err = BlockApply::apply_full_block(&mut store, &block, None, None)
                .expect_err("missing section must error");
            assert!(
                matches!(err, StateError::DigestAdProofsSectionMissing { .. }),
                "got {err:?}"
            );
            // Data-availability, NOT block invalidity.
            assert!(
                !store.session_invalids.contains(&header_id),
                "missing section must not mark the header session-invalid"
            );
            assert_eq!(store.height(), 4);
        }

        #[test]
        fn apply_full_block_trailing_bytes_in_section_is_corruption() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path());
            seed_tip(&mut store, [1u8; 33], 4);
            let ad_root = [0xABu8; 32];
            let header = synth_block_header(5, synth_header_id(4), [1u8; 33], ad_root);
            let (header_id, block) = empty_block(header);
            let mut bytes = section_bytes(header_id, vec![0u8; 8]);
            bytes.push(0xFF); // trailing junk after the proof
            store
                .headers
                .store_block_section_typed(&section_id(header_id, ad_root), &bytes, TYPE_AD_PROOFS)
                .expect("store section");
            let err = BlockApply::apply_full_block(&mut store, &block, None, None)
                .expect_err("trailing bytes must error");
            assert!(
                matches!(
                    err,
                    StateError::DbCorruption {
                        table: "block_sections",
                        ..
                    }
                ),
                "got {err:?}"
            );
            assert_eq!(store.height(), 4);
        }

        #[test]
        fn apply_full_block_section_inner_header_id_mismatch_is_corruption() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path());
            seed_tip(&mut store, [1u8; 33], 4);
            let ad_root = [0xABu8; 32];
            let header = synth_block_header(5, synth_header_id(4), [1u8; 33], ad_root);
            let (header_id, block) = empty_block(header);
            // Section parses cleanly but carries a foreign inner header id.
            let bytes = section_bytes([0x55u8; 32], vec![0u8; 8]);
            store
                .headers
                .store_block_section_typed(&section_id(header_id, ad_root), &bytes, TYPE_AD_PROOFS)
                .expect("store section");
            let err = BlockApply::apply_full_block(&mut store, &block, None, None)
                .expect_err("inner header-id mismatch must error");
            assert!(
                matches!(
                    err,
                    StateError::DbCorruption {
                        table: "block_sections",
                        ..
                    }
                ),
                "got {err:?}"
            );
            assert_eq!(store.height(), 4);
        }

        #[test]
        fn apply_full_block_bad_ad_proofs_root_rejects_and_marks_session_invalid() {
            let tmp = tempdir().expect("tempdir");
            let mut store = open_at(tmp.path());
            seed_tip(&mut store, [1u8; 33], 4);
            // ad_proofs_root the proof bytes do NOT hash to → the
            // verifier's root-hash gate rejects (AdProofsRootMismatch).
            let ad_root = [0xABu8; 32];
            let header = synth_block_header(5, synth_header_id(4), [1u8; 33], ad_root);
            let (header_id, block) = empty_block(header);
            let bytes = section_bytes(header_id, vec![0u8; 8]);
            store
                .headers
                .store_block_section_typed(&section_id(header_id, ad_root), &bytes, TYPE_AD_PROOFS)
                .expect("store section");
            let err = BlockApply::apply_full_block(&mut store, &block, None, None)
                .expect_err("bad ad_proofs_root must be rejected");
            assert!(
                matches!(err, StateError::DigestApplyRejected { .. }),
                "got {err:?}"
            );
            // A verifier rejection is session-scoped invalidity.
            assert!(
                store.session_invalids.contains(&header_id),
                "verifier rejection must mark the header session-invalid"
            );
            assert_eq!(store.height(), 4, "no state advance on rejection");
        }
    }
}
