//! Voted-params genesis-row seeding / presence / key-placement guards
//! for [`super::DigestStateStore`], plus the digest-verifier on-disk
//! marker probe shared with `StateStore`'s state-type inference.
//!
//! Sibling of `mod.rs`; pure impl relocation.

use ergo_validation::ActiveProtocolParameters;
use redb::{Database, ReadableTable};

use crate::active_params;
use crate::store::StateError;

use super::{CHAIN_STATE_HISTORY, DIGEST_HISTORY, ROOT_DIGEST_KEY};

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
pub(super) fn require_genesis_voted_params_match_or_seed(
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
pub(super) fn require_genesis_voted_params_present(db: &Database) -> Result<(), StateError> {
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
pub(super) fn validate_voted_params_keys(
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
