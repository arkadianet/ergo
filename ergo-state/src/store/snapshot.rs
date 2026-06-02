//! `CommittedSnapshot`: a single-read-transaction committed view of the
//! chain and authenticated state, for off-loop mining-candidate builds.
//!
//! The off-loop candidate engine (see the mining-candidate regeneration
//! design) must read every consensus-bearing build input — the best-full
//! and best-header tips, the parent header, the last-10 applied-header
//! window, the active protocol parameters, the validation settings, and
//! the AVL+ state root + node graph — from **one** redb read transaction.
//! `ChainStoreReader` opens a fresh transaction per method, so stitching
//! its calls together could splice inputs across a commit boundary and
//! yield a candidate whose `(state_root, ADProofs)` diverge from an
//! on-loop build. `CommittedSnapshot` holds one [`redb::ReadTransaction`]
//! for its lifetime and sources everything from it, giving a frozen,
//! MVCC-consistent view immune to commits that land after it opened.
//!
//! Consensus parity: [`CommittedSnapshot::candidate_dry_run`] hydrates a
//! throwaway `BatchAVLProver` from this transaction's `AVL_NODES` (no
//! copy-on-write, no persistent tree — the spec forbids both) and then
//! runs the exact same `apply_change_set_to_prover` sequence the on-loop
//! [`StateStore::candidate_dry_run`] uses, so for the same parent and
//! change-set the two produce byte-identical results.

use std::sync::Arc;

use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_primitives::digest::{ADDigest, Digest32};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::Header;
use ergo_validation::{
    ActiveProtocolParameters, CheckedTransaction, ErgoValidationSettings, UtxoView,
};
use redb::{Database, ReadTransaction};

use super::meta::StateMeta;
use super::{
    StateError, StateStore, AVL_NODES, BLOCK_SECTIONS, CHAIN_INDEX, CHAIN_STATE_META, HEADERS,
    HEADER_CHAIN_INDEX, STATE_META,
};
use crate::active_params;
use crate::avl::hydrate::hydrate_batch_avl_prover_from_fetch;
use crate::avl::node::{AvlNode, NodeId, NULL_NODE};
use crate::chain::ChainStateMeta;

/// One redb-read-transaction-backed committed view, for off-loop
/// candidate generation. See the module docs for why a single
/// transaction is load-bearing.
///
/// `Send` (the read transaction and the cached metadata all are), so it
/// can be moved into a background tokio task; it is intentionally not
/// shared (`!Sync` in practice via the held transaction) — each build
/// owns its own snapshot.
pub struct CommittedSnapshot {
    txn: ReadTransaction,
    chain_state: ChainStateMeta,
    state_meta: StateMeta,
}

impl CommittedSnapshot {
    /// Open a snapshot over one fresh read transaction.
    ///
    /// Returns `Ok(None)` only when there is no committed state to build on
    /// — *both* the `chain_state_meta` row and the `state_meta` root row are
    /// absent (a fresh, pre-genesis store). A one-sided presence is a
    /// commit-atomicity violation and returns `Err(DbCorruption)`, as does
    /// physical corruption of either row.
    pub(crate) fn open(db: &Arc<Database>) -> Result<Option<Self>, StateError> {
        let txn = db.begin_read()?;

        // Read both committed-metadata rows up front so we can distinguish a
        // fresh, pre-genesis store (BOTH absent → `Ok(None)`) from corruption
        // (exactly one present). All four state tables commit in one redb
        // transaction (`StateStore::persist_apply` / `initialize_genesis`), so
        // a one-sided presence is a real atomicity-violation signal, not an
        // uninitialized store — surface it rather than silently behaving as
        // "not synced yet".
        let chain_state_bytes: Option<Vec<u8>> = match txn.open_table(CHAIN_STATE_META) {
            Ok(t) => t.get("chain_state")?.map(|g| g.value().to_vec()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(e.into()),
        };
        let state_meta_bytes: Option<Vec<u8>> = match txn.open_table(STATE_META) {
            Ok(t) => t.get("root")?.map(|g| g.value().to_vec()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(e.into()),
        };

        match (chain_state_bytes, state_meta_bytes) {
            (None, None) => Ok(None),
            (Some(cs), Some(sm)) => {
                let chain_state =
                    ChainStateMeta::deserialize(&cs).map_err(|e| StateError::DbCorruption {
                        table: "chain_state_meta",
                        key: hex::encode(b"chain_state"),
                        reason: format!("decode: {e}"),
                    })?;
                let state_meta = StateMeta::deserialize(&sm)?;
                Ok(Some(Self {
                    txn,
                    chain_state,
                    state_meta,
                }))
            }
            (Some(_), None) => Err(StateError::DbCorruption {
                table: "state_meta",
                key: hex::encode(b"root"),
                reason: "chain_state present but state_meta root absent \
                         (commit atomicity violated)"
                    .to_string(),
            }),
            (None, Some(_)) => Err(StateError::DbCorruption {
                table: "chain_state_meta",
                key: hex::encode(b"chain_state"),
                reason: "state_meta root present but chain_state absent \
                         (commit atomicity violated)"
                    .to_string(),
            }),
        }
    }

    /// Committed best-full-block id in this frozen view.
    pub fn best_full_block_id(&self) -> [u8; 32] {
        self.chain_state.best_full_block_id
    }

    /// Committed best-full-block height in this frozen view.
    pub fn best_full_block_height(&self) -> u32 {
        self.chain_state.best_full_block_height
    }

    /// Committed best-header id in this frozen view.
    pub fn best_header_id(&self) -> [u8; 32] {
        self.chain_state.best_header_id
    }

    /// Committed best-header height in this frozen view.
    pub fn best_header_height(&self) -> u32 {
        self.chain_state.best_header_height
    }

    /// The full live mining-gate synced predicate: a committed full block
    /// exists and the header tip equals the full tip. Mirrors the on-loop
    /// gate exactly (height > 0 guard included), so it is never true at
    /// the zeroed genesis state where both ids are `[0; 32]` at height 0.
    pub fn synced(&self) -> bool {
        self.chain_state.best_full_block_height > 0
            && self.chain_state.best_header_height == self.chain_state.best_full_block_height
            && self.chain_state.best_header_id == self.chain_state.best_full_block_id
    }

    /// Committed AVL+ state root — the candidate's parent state root.
    pub fn state_root(&self) -> ADDigest {
        ADDigest::from_bytes(self.state_meta.root_digest)
    }

    /// Raw serialized header bytes stored at `id`, or `None` if absent.
    /// Mirrors `StateStore::get_header`; the candidate builder reads bytes
    /// then parses, so this is the byte-level twin used by the
    /// `CandidateStateView` impl.
    pub fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        let table = match self.txn.open_table(HEADERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(id.as_slice())? {
            Some(g) => Ok(Some(g.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Decode the header stored at `id`, or `None` if absent.
    pub fn header(&self, id: &[u8; 32]) -> Result<Option<Header>, StateError> {
        match self.get_header_bytes(id)? {
            Some(bytes) => {
                let mut r = VlqReader::new(&bytes);
                let header = ergo_ser::header::read_header(&mut r).map_err(|e| {
                    StateError::DbCorruption {
                        table: "headers",
                        key: hex::encode(id),
                        reason: format!("header decode: {e}"),
                    }
                })?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    /// Canonical best-header-chain id at `height`, or `None` if absent.
    /// Reads `HEADER_CHAIN_INDEX` in the held transaction; mirrors
    /// `StateStore::get_header_id_at_height`. Used by the difficulty
    /// retarget's epoch-header lookup.
    pub fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        let table = match self.txn.open_table(HEADER_CHAIN_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(height as u64)? {
            Some(g) => {
                let bytes = g.value();
                if bytes.len() != 32 {
                    return Err(StateError::DbCorruption {
                        table: "header_chain_index",
                        key: hex::encode((height as u64).to_be_bytes()),
                        reason: format!("row has len {} (expected 32)", bytes.len()),
                    });
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(bytes);
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    /// Serialized block-section bytes by modifier_id (extension /
    /// block-transactions / AD-proofs section), or `None` if absent.
    /// Reads `BLOCK_SECTIONS` in the held transaction; mirrors
    /// `StateStore::get_block_section`. Used by the candidate builder for
    /// the parent extension and the emission-box lookup.
    pub fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        let table = match self.txn.open_table(BLOCK_SECTIONS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(modifier_id.as_slice())? {
            Some(g) => Ok(Some(g.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Look up the serialized bytes of an unspent box by id within this
    /// snapshot's one held read transaction. Delegates to the shared
    /// [`crate::reader::lookup_box_in_txn`] so the descent is **byte-identical**
    /// to `ChainStoreReader::lookup_box` (same `parse_walk_node`, which ignores
    /// balance/label bytes irrelevant to descent). `Ok(None)` for an empty tree
    /// or absent key; `Err(DbCorruption)` for a missing/malformed node or a
    /// null internal child.
    pub fn lookup_box(&self, box_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        crate::reader::lookup_box_in_txn(&self.txn, self.state_meta.root_node_id, box_id)
    }

    /// The last 10 applied-chain headers, tip-first (index 0 = the
    /// committed best-full tip). Errors with [`StateError::EarlyIBD`] when
    /// fewer than 10 blocks have been applied. Mirrors
    /// [`StateStore::last_applied_chain_window_10`] but reads from this
    /// snapshot's single transaction.
    pub fn last_headers_window(&self) -> Result<[Header; 10], StateError> {
        let tip_h = self.chain_state.best_full_block_height;
        if tip_h < 10 {
            return Err(StateError::EarlyIBD {
                needed_min: 10,
                observed: tip_h,
            });
        }
        let chain_table = self.txn.open_table(CHAIN_INDEX)?;
        let headers_table = self.txn.open_table(HEADERS)?;

        let mut headers: Vec<Header> = Vec::with_capacity(10);
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
            let mut r = VlqReader::new(hdr_guard.value());
            let header =
                ergo_ser::header::read_header(&mut r).map_err(|e| StateError::DbCorruption {
                    table: "headers",
                    key: hex::encode(id_bytes),
                    reason: format!("last_headers_window: header decode at h={h}: {e}"),
                })?;
            headers.push(header);
        }
        headers
            .try_into()
            .map_err(|_| StateError::InternalInvariant {
                what: "CommittedSnapshot::last_headers_window: built window with size != 10",
            })
    }

    /// Active protocol parameters at the committed tip — the block version
    /// the candidate must carry. Read from `VOTED_PARAMS` in this
    /// transaction; the genesis row written by open's reconcile guarantees
    /// a row exists, so `None` is treated as corruption (mirrors the
    /// on-loop `refresh_cached_active_params`).
    pub fn active_params(&self) -> Result<ActiveProtocolParameters, StateError> {
        let h = self.chain_state.best_full_block_height;
        active_params::read_latest_at(&self.txn, h)?.ok_or(StateError::InternalInvariantAt {
            what: "CommittedSnapshot::active_params: no voted_params row \
                   (genesis row should exist)",
            height: h,
        })
    }

    /// Cumulative validation settings at the committed tip — the activated
    /// script version the candidate validates under. Read from
    /// `VOTED_PARAMS` in this transaction.
    pub fn validation_settings(&self) -> Result<ErgoValidationSettings, StateError> {
        let h = self.chain_state.best_full_block_height;
        // The settings helper returns empty settings when `VOTED_PARAMS` is
        // missing; the on-loop cache path instead hard-fails on a missing row
        // (`refresh_cached_active_params`). Pair the same row-existence check
        // here so a missing/corrupt table surfaces rather than silently
        // yielding empty (= weaker) settings. The genesis row written by
        // open's reconcile guarantees a row exists post-open.
        if active_params::read_latest_at(&self.txn, h)?.is_none() {
            return Err(StateError::InternalInvariantAt {
                what: "CommittedSnapshot::validation_settings: no voted_params row \
                       (genesis row should exist)",
                height: h,
            });
        }
        Ok(active_params::compute_validation_settings_at(&self.txn, h)?)
    }

    /// Hydrate a throwaway `BatchAVLProver` from this snapshot's committed
    /// AVL+ nodes (read from `AVL_NODES` in the held transaction). No
    /// persistent/COW tree is retained — the prover is dropped after the
    /// dry-run.
    pub fn hydrate_prover(&self) -> Result<BatchAVLProver, StateError> {
        let root_id = self.state_meta.root_node_id;
        if root_id == NULL_NODE {
            return Err(StateError::InternalInvariant {
                what: "CommittedSnapshot::hydrate_prover: empty/NULL committed state root",
            });
        }
        let nodes = self.txn.open_table(AVL_NODES)?;
        let fetch = |id: NodeId| -> Result<AvlNode, StateError> {
            let guard = nodes.get(id)?.ok_or_else(|| StateError::DbCorruption {
                table: "avl_nodes",
                key: hex::encode(id.to_be_bytes()),
                reason: format!("missing node id {id} during snapshot hydrate"),
            })?;
            super::node_from_bytes(guard.value())
        };
        hydrate_batch_avl_prover_from_fetch(root_id, self.state_meta.tree_height, &fetch)
    }

    /// Speculatively apply `checked` over this committed snapshot and
    /// return `(new_state_root, raw_ad_proof_bytes, snapshot_tip_id)` —
    /// the off-loop twin of [`StateStore::candidate_dry_run`]. Byte-for-
    /// byte identical to the on-loop result for the same parent + txs.
    pub fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        let (to_remove, to_insert) = StateStore::build_utxo_changes_checked(checked)?;
        let prover = self.hydrate_prover()?;
        let (new_root, proof) =
            super::dry_run::apply_change_set_to_prover(prover, &to_remove, &to_insert)?;
        Ok((new_root, proof, self.chain_state.best_full_block_id))
    }
}

impl UtxoView for CommittedSnapshot {
    /// Box resolution for the in-block candidate overlay, walking the
    /// committed AVL+ via [`CommittedSnapshot::lookup_box`] on the held
    /// transaction. Returns `None` for an absent box OR on a read/walk
    /// error: candidate selection then conservatively skips the
    /// unresolvable input, and the submit-time validator re-resolves
    /// against live state and is authoritative — so a transient read error
    /// can only drop a tx from the template, never admit an invalid one.
    /// (Mirrors `StateStore::get_box`, which likewise yields `None` on a
    /// box-bytes decode failure.)
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        let bytes = match self.lookup_box(box_id.as_bytes()) {
            Ok(opt) => opt?,
            Err(e) => {
                // Committed-state corruption or a snapshot-read fault. Candidate
                // selection then skips the unresolvable input (invalid-block
                // safe — the submit-time validator re-resolves against live
                // state and is authoritative), but the fault must NOT be silent
                // at this off-loop box-resolution seam: surface it loudly so an
                // operator sees a degraded template's cause.
                tracing::error!(
                    box_id = %hex::encode(box_id.as_bytes()),
                    error = ?e,
                    "CommittedSnapshot::get_box: committed-state box lookup failed; \
                     treating box as unresolved (candidate input will be skipped)"
                );
                return None;
            }
        };
        let mut r = VlqReader::new(&bytes);
        read_ergo_box(&mut r).ok()
    }
}

impl StateStore {
    /// Open a [`CommittedSnapshot`] over the committed (durable) state —
    /// the single-transaction view the off-loop candidate engine builds
    /// from. Returns `Ok(None)` for a store with no committed state.
    ///
    /// The snapshot reflects the last redb commit, which can trail the
    /// in-memory applied tip by the persist-pipeline queue depth; callers
    /// that need a specific tip compare `best_full_block_id()` against
    /// their expected parent and retry.
    pub fn committed_snapshot(&self) -> Result<Option<CommittedSnapshot>, StateError> {
        CommittedSnapshot::open(&self.db)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::store::dry_run::{
        apply_change_set_to_prover, apply_change_set_via_prover, DryRunInsertMap, DryRunRemoveMap,
    };
    use crate::store::{
        StateError, StateStore, AVL_NODES, BLOCK_SECTIONS, HEADER_CHAIN_INDEX, STATE_META,
    };

    // ----- helpers -----

    fn box_id(seed: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[31] = seed;
        id
    }

    fn genesis_store() -> (tempfile::TempDir, StateStore) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(dir.path().join("s.redb").as_path()).unwrap();
        store
            .initialize_genesis(&[
                (box_id(1), vec![0x11u8; 40]),
                (box_id(2), vec![0x22u8; 48]),
                (box_id(3), vec![0x33u8; 56]),
            ])
            .unwrap();
        (dir, store)
    }

    // ----- oracle parity -----

    /// The headline consensus guarantee under MUTATION: a mixed
    /// remove+insert batch dry-run produces byte-identical `(state_root,
    /// proof)` whether the prover is hydrated from the live in-memory arena
    /// (on-loop) or from the committed redb snapshot (off-loop). Both paths
    /// share `apply_change_set_to_prover`, so this isolates the one
    /// remaining divergence surface — the hydrated node graph — under
    /// operations that actually walk and rewrite it (the integration
    /// `committed_snapshot_parity` test only covers the empty batch).
    #[test]
    fn nonempty_dry_run_parity_live_tree_vs_snapshot() {
        let (_dir, store) = genesis_store();

        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(box_id(2), ());
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(box_id(9), vec![0x99u8; 44]);

        // On-loop: hydrate from the live in-memory tree.
        let oracle =
            apply_change_set_via_prover(&store.tree, &to_remove, &to_insert).expect("live dry-run");

        // Off-loop: hydrate from the committed snapshot's single read txn.
        let snap = store.committed_snapshot().unwrap().expect("snapshot");
        let prover = snap.hydrate_prover().expect("snapshot hydrate");
        let got = apply_change_set_to_prover(prover, &to_remove, &to_insert).expect("snap dry-run");

        assert_eq!(
            oracle.0, got.0,
            "non-empty batch state_root must be byte-identical"
        );
        assert_eq!(
            oracle.1, got.1,
            "non-empty batch ad_proof bytes must be byte-identical"
        );
    }

    // ----- error paths -----

    #[test]
    fn open_errors_on_one_sided_metadata() {
        let (_dir, store) = genesis_store();
        // Corrupt: drop STATE_META["root"] while CHAIN_STATE_META stays —
        // an atomicity violation that must surface, not read as pre-genesis.
        {
            let wt = crate::begin_write_qr(&store.db).unwrap();
            {
                let mut t = wt.open_table(STATE_META).unwrap();
                t.remove("root").unwrap();
            }
            wt.commit().unwrap();
        }
        let res = store.committed_snapshot();
        assert!(
            matches!(res, Err(StateError::DbCorruption { .. })),
            "expected DbCorruption on one-sided metadata"
        );
    }

    #[test]
    fn hydrate_errors_when_advertised_root_node_missing() {
        let (_dir, store) = genesis_store();
        let root_id = store
            .committed_snapshot()
            .unwrap()
            .expect("snapshot")
            .state_meta
            .root_node_id;
        // Delete the advertised root node from AVL_NODES.
        {
            let wt = crate::begin_write_qr(&store.db).unwrap();
            {
                let mut t = wt.open_table(AVL_NODES).unwrap();
                t.remove(root_id).unwrap();
            }
            wt.commit().unwrap();
        }
        // A fresh snapshot opens (metadata intact) but hydration must
        // surface the missing node as corruption, never a silent miss.
        let snap = store.committed_snapshot().unwrap().expect("snapshot2");
        let res = snap.hydrate_prover();
        assert!(
            matches!(res, Err(StateError::DbCorruption { .. })),
            "expected DbCorruption for missing root node"
        );
    }

    // ----- new-read parity (block_section, header_id_at_height) -----

    #[test]
    fn new_reads_match_store_oracle() {
        let (_dir, store) = genesis_store();

        // Seed a block section + a header-chain-index row directly into the
        // committed tables (raw write commits immediately, sidestepping any
        // persist-pipeline buffering), so both readers observe identical bytes.
        let sec_id = box_id(0xB5);
        let sec_bytes = vec![0xEEu8; 73];
        let hci_height = 4242u32;
        let hci_id = box_id(0x7C);
        {
            let wt = crate::begin_write_qr(&store.db).unwrap();
            {
                let mut t = wt.open_table(BLOCK_SECTIONS).unwrap();
                t.insert(sec_id.as_slice(), sec_bytes.as_slice()).unwrap();
            }
            {
                let mut t = wt.open_table(HEADER_CHAIN_INDEX).unwrap();
                t.insert(hci_height as u64, hci_id.as_slice()).unwrap();
            }
            wt.commit().unwrap();
        }

        let snap = store.committed_snapshot().unwrap().expect("snapshot");

        // block_section: snapshot reads the same bytes as the StateStore oracle.
        assert_eq!(
            snap.block_section(&sec_id).unwrap(),
            store.get_block_section(&sec_id).unwrap(),
            "block_section must match StateStore oracle"
        );
        assert_eq!(snap.block_section(&sec_id).unwrap(), Some(sec_bytes));
        assert_eq!(
            snap.block_section(&box_id(0xAA)).unwrap(),
            None,
            "absent section must be None"
        );

        // header_id_at_height: snapshot reads the same id as the oracle.
        assert_eq!(
            snap.header_id_at_height(hci_height).unwrap(),
            store.get_header_id_at_height(hci_height).unwrap(),
            "header_id_at_height must match StateStore oracle"
        );
        assert_eq!(snap.header_id_at_height(hci_height).unwrap(), Some(hci_id));
        assert_eq!(
            snap.header_id_at_height(99_999).unwrap(),
            None,
            "absent height must be None"
        );
    }

    #[test]
    fn header_id_at_height_rejects_malformed_row() {
        let (_dir, store) = genesis_store();
        let bad_height = 7u32;
        {
            let wt = crate::begin_write_qr(&store.db).unwrap();
            {
                let mut t = wt.open_table(HEADER_CHAIN_INDEX).unwrap();
                // 31 bytes — not a valid 32-byte header id.
                t.insert(bad_height as u64, [0u8; 31].as_slice()).unwrap();
            }
            wt.commit().unwrap();
        }
        let snap = store.committed_snapshot().unwrap().expect("snapshot");
        let res = snap.header_id_at_height(bad_height);
        assert!(
            matches!(res, Err(StateError::DbCorruption { .. })),
            "malformed header_chain_index row must surface DbCorruption"
        );
    }

    // ----- box-resolution parity (lookup_box / UtxoView) -----

    #[test]
    fn box_lookup_matches_store_oracle() {
        let (_dir, store) = genesis_store();
        let snap = store.committed_snapshot().unwrap().expect("snapshot");
        // The snapshot and the ChainStoreReader share the exact same descent
        // (`reader::lookup_box_in_txn`), so the reader is the authoritative
        // oracle here; also cross-check the raw StateStore bytes.
        let reader = store.reader_handle();

        for seed in [1u8, 2, 3] {
            let id = box_id(seed);
            let got = snap.lookup_box(&id).unwrap();
            assert_eq!(
                got,
                reader.lookup_box(&id).unwrap(),
                "lookup_box must match ChainStoreReader::lookup_box for box {seed}"
            );
            assert_eq!(
                got,
                store.get_box_bytes(&id),
                "lookup_box must match StateStore::get_box_bytes for box {seed}"
            );
            assert!(got.is_some(), "genesis box {seed} must be present");
        }

        // Absent box: snapshot, reader, and store all resolve to None without
        // erroring.
        let absent = box_id(0xAA);
        assert_eq!(snap.lookup_box(&absent).unwrap(), None);
        assert_eq!(reader.lookup_box(&absent).unwrap(), None);
        assert_eq!(store.get_box_bytes(&absent), None);
    }

    #[test]
    fn box_lookup_corruption_matches_reader() {
        let (_dir, store) = genesis_store();
        // Capture the committed root, then delete it from AVL_NODES so any
        // descent hits a missing advertised node.
        let root_id = store
            .committed_snapshot()
            .unwrap()
            .expect("snapshot")
            .state_meta
            .root_node_id;
        {
            let wt = crate::begin_write_qr(&store.db).unwrap();
            {
                let mut t = wt.open_table(AVL_NODES).unwrap();
                t.remove(root_id).unwrap();
            }
            wt.commit().unwrap();
        }
        // Fresh snapshot + reader both see the corruption and surface it
        // identically (they share `reader::lookup_box_in_txn`).
        let snap = store.committed_snapshot().unwrap().expect("snapshot2");
        let reader = store.reader_handle();
        let probe = box_id(1);
        assert!(
            matches!(
                snap.lookup_box(&probe),
                Err(StateError::DbCorruption { .. })
            ),
            "snapshot lookup_box must surface DbCorruption on a missing node"
        );
        assert!(
            matches!(
                reader.lookup_box(&probe),
                Err(StateError::DbCorruption { .. })
            ),
            "reader lookup_box must surface DbCorruption identically"
        );
    }

    // NOTE: legacy v1 internal-node (tag 0x01) coverage through the
    // snapshot path is intentionally not added here. The node writer only
    // emits v2 (tag 0x02); crafting v1 bytes by hand would test our own
    // synthetic encoding (a self-oracle), not real persisted state. The
    // hydrate boundary ignores the only v1/v2-differing fields (cached
    // child labels), so the structural walk is format-agnostic — see the
    // note in `avl/hydrate.rs`.
}
