//! Open-time loading for [`super::DigestStateStore`]: `open`, the
//! three-shape consistency reconstructor `read_consistent_state`, and
//! its density / genesis cross-check helpers.
//!
//! Sibling of `mod.rs`; pure impl relocation.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use ergo_validation::ActiveProtocolParameters;
use redb::{Database, ReadableTable, ReadableTableMetadata};

use crate::chain::ChainStateMeta;
use crate::store::StateError;

use super::{
    chain_state_internal_invariant, decode_32_bytes, decode_33_bytes, genesis_chain_state,
    require_genesis_voted_params_match_or_seed, require_genesis_voted_params_present,
    require_root_matches_tip_header, validate_voted_params_keys, DigestStateStore,
    CHAIN_STATE_HISTORY, CHAIN_STATE_KEY, DIGEST_HISTORY, DIGEST_VERIFIER_STATE_TYPE,
    ROOT_DIGEST_KEY,
};

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
