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
use std::sync::Arc;

use ergo_validation::{ActiveProtocolParameters, ErgoValidationSettings};
use redb::{Database, ReadableTable, TableDefinition};

use crate::active_params;
use crate::chain::ChainStateMeta;
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

mod apply;
mod open;

impl DigestStateStore {
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
