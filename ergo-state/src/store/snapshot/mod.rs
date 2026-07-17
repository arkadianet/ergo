//! `CommittedSnapshot`: a single-read-transaction committed view of the
//! chain and authenticated state, for off-loop mining-candidate builds.
//!
//! The off-loop candidate engine must read every consensus-bearing build input — the best-full
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
use ergo_avltree_rust::batch_node::AVLTree as OracleTree;
use ergo_primitives::digest::{ADDigest, Digest32};
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::Header;
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_ser::transaction::Transaction;
use ergo_validation::{
    ActiveProtocolParameters, CheckedTransaction, ErgoValidationSettings, UtxoView,
};
use redb::{Database, ReadTransaction, ReadableTable};

use super::meta::StateMeta;
use super::{
    StateError, StateStore, AVL_NODES, BLOCK_SECTIONS, CHAIN_INDEX, CHAIN_STATE_META, HEADERS,
    HEADER_CHAIN_INDEX, MODE2_TRUST_FIRST_EPOCH_KEY, STATE_META,
};
use crate::active_params;
use crate::avl::hydrate::{batch_avl_prover_from_tree, hydrate_tree_from_fetch};
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

    /// Whether the Mode 2 (UTXO-snapshot) first-epoch trust sentinel is armed
    /// in this committed view — i.e. the local cumulative validation settings
    /// are still the launch defaults pending the first trusted post-snapshot
    /// epoch-boundary apply. Read from the persisted
    /// `CHAIN_STATE_META[MODE2_TRUST_FIRST_EPOCH_KEY]` (first byte `0x01`), so it
    /// matches the on-loop `StateStore::is_mode2_trust_first_epoch_armed` at the
    /// same committed point. The candidate builder refuses epoch-boundary mining
    /// while armed, since it cannot yet serialize the real cumulative settings.
    pub fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError> {
        match self.txn.open_table(CHAIN_STATE_META) {
            Ok(t) => Ok(t
                .get(MODE2_TRUST_FIRST_EPOCH_KEY)?
                .map(|g| g.value().first().copied() == Some(0x01))
                .unwrap_or(false)),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
            Err(e) => Err(e.into()),
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

    /// Hydrate the upstream `AVLTree` (the materialized `Rc<RefCell<Node>>`
    /// graph) and its height from this snapshot's committed AVL+ nodes (read
    /// from `AVL_NODES` in the held transaction).
    ///
    /// This is the single hydration implementation shared by the uncached
    /// dry-run ([`Self::hydrate_prover`] → [`Self::candidate_dry_run`]) and
    /// the cached dry-run ([`Self::candidate_dry_run_cached`], which memoizes
    /// the returned tree as a per-tip [`DryRunBase`]). Sharing it is what
    /// guarantees a reused base is structurally identical to a fresh hydrate.
    fn hydrate_tree(&self) -> Result<(OracleTree, u8), StateError> {
        let root_id = self.state_meta.root_node_id;
        if root_id == NULL_NODE {
            return Err(StateError::InternalInvariant {
                what: "CommittedSnapshot::hydrate_tree: empty/NULL committed state root",
            });
        }
        let height = self.state_meta.tree_height;
        let nodes = self.txn.open_table(AVL_NODES)?;

        // Sequential preload, then build from RAM. The structural hydrate below
        // (`hydrate_tree_from_fetch`) is a root-to-leaf DFS keyed by child
        // NodeId, and NodeIds are NOT tree-local — so fetching each node
        // straight from redb is a random B-tree point lookup. That pointer-chase
        // is fine when the AVL pages are warm, but under memory pressure the
        // pages are cold and each lookup faults one scattered 4 KiB read from
        // swap; a full hydrate then degrades from ~seconds to minutes (observed
        // ~500 major faults/s on the mainnet archival node). Instead we stream
        // the whole `AVL_NODES` table once in key order — a single sequential,
        // readahead-friendly scan — into a map, then build the tree from RAM
        // with no further disk I/O.
        //
        // Memory: a `BTreeMap`, NOT a `HashMap`, is load-bearing here. `remove`
        // hands each node to the tree as it is consumed (every node is hydrated
        // exactly once — this is a tree, not a DAG), and a `BTreeMap` frees its
        // internal B-tree node allocations as it shrinks, so the map drains
        // while the Oracle tree fills and peak stays near one tree's worth. A
        // `HashMap` would instead retain its full bucket array (sized for every
        // node, never shrunk by `remove`) until it dropped, stacking a transient
        // ~1x of the whole UTXO node set on top of the hydrated tree — a
        // multi-GB RSS spike in exactly the memory-pressure path this preload is
        // meant to relieve. Insertion is from the already-sorted scan, so the
        // tree stays cheap to build. This runs only on the cold path (no base
        // cache, a cache miss, or a multi-block jump); the per-build steady
        // state goes through the base cache's incremental advance and never
        // lands here.
        let mut node_map: std::collections::BTreeMap<NodeId, AvlNode> =
            std::collections::BTreeMap::new();
        for entry in nodes.iter()? {
            let (k, v) = entry?;
            node_map.insert(k.value(), super::node_from_bytes(v.value())?);
        }
        let node_map = std::cell::RefCell::new(node_map);
        let fetch = |id: NodeId| -> Result<AvlNode, StateError> {
            node_map
                .borrow_mut()
                .remove(&id)
                .ok_or_else(|| StateError::DbCorruption {
                    table: "avl_nodes",
                    key: hex::encode(id.to_be_bytes()),
                    reason: format!("missing node id {id} during snapshot hydrate"),
                })
        };
        let tree = hydrate_tree_from_fetch(root_id, height, &fetch)?;
        Ok((tree, height))
    }

    /// Hydrate a throwaway `BatchAVLProver` from this snapshot's committed
    /// AVL+ nodes (read from `AVL_NODES` in the held transaction). No
    /// persistent/COW tree is retained — the prover is dropped after the
    /// dry-run.
    pub fn hydrate_prover(&self) -> Result<BatchAVLProver, StateError> {
        let (tree, _height) = self.hydrate_tree()?;
        Ok(batch_avl_prover_from_tree(tree))
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
        let to_lookup = StateStore::build_data_input_lookups_checked(checked);
        let mut prover = self.hydrate_prover()?;
        let (new_root, proof) = super::dry_run::apply_change_set_to_prover(
            &mut prover,
            &to_lookup,
            &to_remove,
            &to_insert,
        )?;
        // Pre-broadcast self-check (see self_check_candidate_proof).
        super::dry_run::self_check_candidate_proof(
            &self.state_root(),
            &to_lookup,
            &to_remove,
            &to_insert,
            &proof,
            &new_root,
        )?;
        Ok((new_root, proof, self.chain_state.best_full_block_id))
    }

    /// Test-only uncached oracle taking pre-built change-maps. Byte-identical
    /// to [`Self::candidate_dry_run`] (same `hydrate_prover` +
    /// `apply_change_set_to_prover`); exists only because the public method
    /// takes `&[CheckedTransaction]`, which cannot be forged in unit tests.
    #[cfg(test)]
    pub(crate) fn candidate_dry_run_via_changes_for_test(
        &self,
        to_lookup: &[[u8; 32]],
        to_remove: &super::dry_run::DryRunRemoveMap,
        to_insert: &super::dry_run::DryRunInsertMap,
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        let mut prover = self.hydrate_prover()?;
        let (new_root, proof) = super::dry_run::apply_change_set_to_prover(
            &mut prover,
            to_lookup,
            to_remove,
            to_insert,
        )?;
        Ok((new_root, proof, self.chain_state.best_full_block_id))
    }

    /// Cached variant of [`Self::candidate_dry_run`]: reuses `base` when it
    /// matches this snapshot's committed tip, otherwise full-hydrates and
    /// memoizes the pristine tree once for this tip. Returns
    /// `(new_state_root, raw_ad_proof_bytes, snapshot_tip_id)` **bit-identical**
    /// to the uncached path for the same parent + change-set — the uncached
    /// path is the oracle.
    ///
    /// Cache key is the committed `best_full_block_id` ONLY: any tip change
    /// (advance OR equal-height reorg) misses and rehydrates. `state_root` is
    /// carried for a `debug_assert` cross-check, never as a key.
    ///
    /// `disposition` is set to the path taken: [`BaseDisposition::Hit`] when
    /// the tip matched the cached base, [`BaseDisposition::Advanced`] when a
    /// single-step advance succeeded, [`BaseDisposition::RehydratedAfterFailedAdvance`]
    /// when advance was attempted but failed (and full rehydrate ran instead),
    /// or [`BaseDisposition::Rehydrated`] when there was no base to advance
    /// (cold start). If the method returns `Err`, `disposition` is set to the
    /// path taken up to the failure point (e.g. `Rehydrated` if a fresh
    /// hydrate itself fails, `RehydratedAfterFailedAdvance` if the advance
    /// failed and then the hydrate failed, `Hit` if the proof step after a
    /// cache hit failed).
    ///
    /// Poison contract (consensus-critical): each build clones the pristine
    /// `base.tree` (shallow O(1) `Rc` clone) and runs ops on the clone. Ops
    /// copy-on-write structural nodes (their `is_new == false`), so the base's
    /// structure is never mutated — BUT they transiently set `visited` flags on
    /// the *shared* nodes, and only a completed `generate_proof` clears them
    /// (via `pack_tree`'s post-order `mark_visited(false)`). `BatchAVLProver::new`
    /// does not sanitize, so reusing a base whose shared nodes still carry dirty
    /// `visited` bits would emit wrong proof bytes silently. Therefore any error
    /// — or panic — between the first op and proof completion HARD-DROPS the base:
    /// the next call rehydrates a clean one. A success leaves the base reusable.
    pub fn candidate_dry_run_cached(
        &self,
        base: &mut Option<DryRunBase>,
        checked: &[CheckedTransaction],
        disposition: &mut Option<BaseDisposition>,
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        let (to_remove, to_insert) = StateStore::build_utxo_changes_checked(checked)?;
        let to_lookup = StateStore::build_data_input_lookups_checked(checked);
        self.candidate_dry_run_cached_with_changes(
            base,
            &to_lookup,
            &to_remove,
            &to_insert,
            disposition,
        )
    }

    /// Try to advance a stale `DryRunBase` (cached at tip N) by applying
    /// block N+1 (the current committed tip) in-place, without a full
    /// rehydrate from `AVL_NODES`.
    ///
    /// Returns `Ok(advanced_base)` only when every step succeeds AND the
    /// advanced digest agrees with `self.state_root()`. Any failure — wrong
    /// parent, missing section, decode error, prover error, or digest
    /// mismatch — returns `Err`, and the caller falls back to full rehydrate.
    /// The consumed `base` tree is dropped on the error path; it is never
    /// reused after this call regardless of the outcome.
    fn try_advance_base(&self, base: DryRunBase) -> Result<DryRunBase, StateError> {
        let tip = self.best_full_block_id();

        // 1. The current committed tip's header must have base.tip_id as parent
        //    (single-step descendant gate).
        let h = self.header(&tip)?.ok_or(StateError::InternalInvariant {
            what: "try_advance_base: committed tip header missing",
        })?;
        if h.parent_id.as_bytes() != &base.tip_id {
            return Err(StateError::InternalInvariant {
                what: "try_advance_base: tip parent != base tip_id (not single-step)",
            });
        }

        // 2. Look up the BlockTransactions section for the current tip.
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &tip,
            h.transactions_root.as_bytes(),
        );
        let bytes = self
            .block_section(&section_id)?
            .ok_or(StateError::InternalInvariant {
                what: "try_advance_base: BlockTransactions section not stored for current tip",
            })?;

        // 3. Decode and sanity-check the header_id linkage.
        let bt = read_block_transactions(&mut VlqReader::new(&bytes))
            .map_err(|e| StateError::Serialization(format!("try_advance_base: {e}")))?;
        if bt.header_id.as_bytes() != &tip {
            return Err(StateError::InternalInvariant {
                what: "try_advance_base: decoded BlockTransactions header_id != tip",
            });
        }

        // 4. Build the canonical netting change set from the raw transactions,
        //    plus the data-input lookup prefix (digest-neutral — the proof is
        //    discarded below — but kept so this path runs the identical
        //    canonical op stream as every other prover consumer).
        let refs: Vec<&Transaction> = bt.transactions.iter().collect();
        let (to_remove, to_insert) = StateStore::build_utxo_changes_raw(&refs)?;
        let to_lookup: Vec<[u8; 32]> = bt
            .transactions
            .iter()
            .flat_map(|tx| tx.data_inputs.iter().map(|di| *di.box_id.as_bytes()))
            .collect();

        // 5. Wrap the consumed base.tree in a prover, apply the change set
        //    via the shared `apply_change_set_to_prover` path (same
        //    removes-ascending-then-inserts-ascending order, same
        //    generate_proof flag cleanup). Taking `&mut` lets us extract the
        //    post-op tree directly from the prover instead of doing a second
        //    full rehydrate. Discard the proof bytes — only the post-op
        //    digest and tree are needed here.
        let mut prover = batch_avl_prover_from_tree(base.tree);
        let (advanced_digest, _proof) = super::dry_run::apply_change_set_to_prover(
            &mut prover,
            &to_lookup,
            &to_remove,
            &to_insert,
        )?;

        // 6. Mandatory digest check (NOT debug_assert): the advanced digest
        //    must equal the snapshot's committed state_root. Mirrors the live
        //    apply's hard-fail (apply.rs ~541) — wrongness must be
        //    structurally unservable.
        let expected = self.state_root();
        if advanced_digest != expected {
            return Err(StateError::DigestMismatch {
                computed: hex::encode(advanced_digest.as_bytes()),
                expected: hex::encode(expected.as_bytes()),
            });
        }

        // 7. Extract the post-generate_proof tree directly from the prover.
        //    `generate_proof` (called inside `apply_change_set_to_prover`)
        //    clears `visited` flags on all shared nodes via `pack_tree`'s
        //    post-order `mark_visited(false)`, so the tree is pristine for
        //    reuse as a new base. `tree_height` is read from the oracle tree's
        //    `height` field, which the AVL ops kept up to date, not
        //    recomputed.
        let tree = prover.base.tree;
        let tree_height = tree.height as u8;
        Ok(DryRunBase {
            tip_id: tip,
            state_root: expected,
            tree,
            tree_height,
        })
    }

    /// Change-map core of [`Self::candidate_dry_run_cached`]. Split out so the
    /// hard-drop / poison contract can be exercised directly with a change set
    /// (a `CheckedTransaction` is unforgeable outside `ergo-validation`, so the
    /// forced-error test drives a remove-of-a-missing-key here). The public
    /// entry point and the uncached oracle both build the maps via the one
    /// `build_utxo_changes_checked` netting builder, keeping the two paths
    /// structurally parallel.
    ///
    /// `disposition` is filled with the path taken (see
    /// [`CommittedSnapshot::candidate_dry_run_cached`] for the contract).
    pub(crate) fn candidate_dry_run_cached_with_changes(
        &self,
        base: &mut Option<DryRunBase>,
        to_lookup: &[[u8; 32]],
        to_remove: &super::dry_run::DryRunRemoveMap,
        to_insert: &super::dry_run::DryRunInsertMap,
        disposition: &mut Option<BaseDisposition>,
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        let tip = self.best_full_block_id();

        // Miss or stale tip: attempt a single-step advance if we have a stale
        // base, otherwise fall back to full rehydrate. Drop the old base slot
        // first so peak memory never holds two graphs simultaneously.
        if base.as_ref().map(|b| b.tip_id) != Some(tip) {
            let old_base = base.take();
            let new_base = match old_base {
                Some(stale) => match self.try_advance_base(stale) {
                    Ok(advanced) => {
                        *disposition = Some(BaseDisposition::Advanced);
                        advanced
                    }
                    Err(e) => {
                        tracing::debug!(
                            error = ?e,
                            "dry-run base advance failed; falling back to full rehydrate",
                        );
                        *disposition = Some(BaseDisposition::RehydratedAfterFailedAdvance);
                        let (tree, tree_height) = self.hydrate_tree()?;
                        DryRunBase {
                            tip_id: tip,
                            state_root: self.state_root(),
                            tree,
                            tree_height,
                        }
                    }
                },
                None => {
                    *disposition = Some(BaseDisposition::Rehydrated);
                    let (tree, tree_height) = self.hydrate_tree()?;
                    DryRunBase {
                        tip_id: tip,
                        state_root: self.state_root(),
                        tree,
                        tree_height,
                    }
                }
            };
            *base = Some(new_base);
        } else {
            *disposition = Some(BaseDisposition::Hit);
        }

        // Shallow COW clone of the pristine base. Ops copy `is_new == false`
        // nodes; the base structure is untouched. `visited` bits ARE dirtied on
        // the shared nodes during ops and cleaned by `generate_proof` — so a
        // failure (or panic) before proof completion must poison the base.
        // Done before the guard's mutable borrow takes over the slot.
        let mut prover = {
            let b = base
                .as_ref()
                .expect("base ensured present for this tip just above");
            debug_assert_eq!(
                b.state_root,
                self.state_root(),
                "DryRunBase/snapshot state-root divergence for the same committed tip"
            );
            batch_avl_prover_from_tree(b.tree.clone())
        };

        // Arm the poison guard: if ops/proof unwind (panic) past here, or we
        // return an Err below, the base is dropped before the next caller sees
        // it. Disarmed only on a fully successful build (proof generated ⇒
        // shared `visited` bits clean).
        let mut guard = PoisonGuard { base: Some(base) };
        match super::dry_run::apply_change_set_to_prover(
            &mut prover,
            to_lookup,
            to_remove,
            to_insert,
        ) {
            Ok((new_root, proof)) => {
                // Pre-broadcast self-check (see self_check_candidate_proof).
                // Runs BEFORE the guard is disarmed: a failure means the
                // proof is unservable, and although `generate_proof`
                // completed (shared `visited` bits are clean), dropping the
                // base via the armed guard is the conservative choice — the
                // next build rehydrates from committed state rather than
                // trusting a base that just produced an unverifiable proof.
                super::dry_run::self_check_candidate_proof(
                    &self.state_root(),
                    to_lookup,
                    to_remove,
                    to_insert,
                    &proof,
                    &new_root,
                )?;
                // Success: the just-run `generate_proof` cleaned the shared
                // `visited` bits, so the base stays reusable for the next
                // same-tip build.
                guard.disarm();
                Ok((new_root, proof, tip))
            }
            // Err: guard's `Drop` hard-drops the (possibly dirty) base on the
            // way out of this scope.
            Err(e) => Err(e),
        }
    }
}

/// Which path served a cached dry-run. Surfaced to the mining engine's build
/// log so operators can see base reuse vs advance vs rehydrate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseDisposition {
    /// Tip matched the cached base — no tree work, just a COW clone.
    Hit,
    /// Single-step advance of a stale base succeeded — one block rolled
    /// forward without a full UTXO-graph rehydrate.
    Advanced,
    /// No prior base existed; full rehydrate from `AVL_NODES`.
    Rehydrated,
    /// A single-step advance was attempted but failed; fell back to full
    /// rehydrate. The failure reason is logged at `debug` at the fallback
    /// site so operators can investigate chronic occurrences.
    RehydratedAfterFailedAdvance,
}

/// Pristine hydrated AVL base for one committed tip, reused across same-tip
/// candidate builds so full UTXO-graph hydration happens once per block
/// instead of once per build.
///
/// Poison contract: the shared-node `visited` flags are clean ⇔ the last use
/// either completed `generate_proof` or the base was dropped. A build that
/// runs ops without reaching `generate_proof` (error/panic) leaves `visited`
/// bits dirty on the shared graph; reusing such a base would emit silently
/// wrong proofs. [`CommittedSnapshot::candidate_dry_run_cached`] enforces the
/// contract by hard-dropping the base on any such failure.
///
/// `!Send`: the inner `Rc<RefCell<Node>>` graph cannot cross a thread
/// boundary, so the base lives on a single dedicated build thread (one serial
/// consumer — never shared).
pub struct DryRunBase {
    tip_id: [u8; 32],
    /// Debug cross-check only — never part of the cache key.
    state_root: ADDigest,
    tree: OracleTree,
    tree_height: u8,
}

impl DryRunBase {
    /// Committed best-full-block id this base was hydrated for (the cache key).
    pub fn tip_id(&self) -> [u8; 32] {
        self.tip_id
    }

    /// Hydrated tree height (debug/instrumentation; the prover carries its own).
    pub fn tree_height(&self) -> u8 {
        self.tree_height
    }

    /// Identity of the hydrated root node (the `Rc` allocation address). Two
    /// calls returning the same id prove the same memoized base was reused —
    /// i.e. a cache hit did NOT rehydrate. Test-only: it leaks an allocation
    /// address and must never be part of shipped behavior.
    #[cfg(test)]
    fn root_identity(&self) -> Option<usize> {
        self.tree
            .root
            .as_ref()
            .map(|r| std::rc::Rc::as_ptr(r) as usize)
    }
}

/// Drop-guard that hard-drops a [`DryRunBase`] unless explicitly disarmed.
///
/// Armed immediately before the first prover op and disarmed only after a
/// completed `generate_proof`. So whether the dry-run returns `Err` or unwinds
/// on a panic between the first op and proof completion, the (possibly
/// `visited`-dirty) base is set to `None` before any later caller can reuse it.
struct PoisonGuard<'a> {
    base: Option<&'a mut Option<DryRunBase>>,
}

impl PoisonGuard<'_> {
    fn disarm(&mut self) {
        self.base = None;
    }
}

impl Drop for PoisonGuard<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.base.take() {
            *slot = None;
        }
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
mod tests;
