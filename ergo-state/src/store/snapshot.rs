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
mod tests {
    use std::collections::BTreeMap;

    use crate::store::dry_run::{
        apply_change_set_to_prover, apply_change_set_via_prover, DryRunInsertMap, DryRunRemoveMap,
    };
    use crate::store::{
        BaseDisposition, StateError, StateStore, AVL_NODES, BLOCK_SECTIONS, HEADER_CHAIN_INDEX,
        STATE_META,
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

    /// The off-loop `CommittedSnapshot` must report the Mode 2 first-epoch trust
    /// sentinel identically to the on-loop `StateStore` at the same committed
    /// point — they read the SAME persisted/in-memory flag. The candidate
    /// builder refuses epoch-boundary mining while armed, so a disagreement
    /// between the two build paths could let the off-loop path emit an invalid
    /// boundary extension. This pins their agreement.
    #[test]
    fn committed_snapshot_mode2_trust_matches_on_loop() {
        let (_dir, mut store) = genesis_store();
        // Fresh store: not armed, and the off-loop view agrees.
        assert!(!store.is_mode2_trust_first_epoch_armed());
        let snap = store.committed_snapshot().unwrap().expect("snapshot");
        assert!(
            !snap.mode2_trust_first_epoch_armed().unwrap(),
            "off-loop must match on-loop (not armed)"
        );
        drop(snap);

        // Arm the sentinel (persists to CHAIN_STATE_META + sets the in-memory
        // mirror), as a UTXO-snapshot install would.
        store.arm_mode2_trust_first_epoch_internal().unwrap();
        assert!(store.is_mode2_trust_first_epoch_armed(), "on-loop armed");

        // A fresh snapshot reads the persisted sentinel — off-loop agrees.
        let snap2 = store.committed_snapshot().unwrap().expect("snapshot2");
        assert!(
            snap2.mode2_trust_first_epoch_armed().unwrap(),
            "off-loop must see the armed persisted sentinel"
        );
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
        let oracle = apply_change_set_via_prover(&store.tree, &[], &to_remove, &to_insert)
            .expect("live dry-run");

        // Off-loop: hydrate from the committed snapshot's single read txn.
        let snap = store.committed_snapshot().unwrap().expect("snapshot");
        let mut prover = snap.hydrate_prover().expect("snapshot hydrate");
        let got = apply_change_set_to_prover(&mut prover, &[], &to_remove, &to_insert)
            .expect("snap dry-run");

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

    // ----- cached dry-run: hit identity + hard-drop contract -----

    /// 3 consecutive same-tip cached calls (1 miss + 2 hits) each bit-equal
    /// the uncached oracle, and the 2 hits reuse the SAME memoized base (no
    /// rehydrate) — proven by `Rc` root identity holding across calls. This
    /// is the post-`generate_proof` flag-cleanup guarantee: a hit on a base
    /// whose `visited` bits were left dirty would emit divergent proof bytes.
    #[test]
    fn cached_same_tip_repeat_matches_uncached_and_reuses_base() {
        let (_dir, store) = genesis_store();

        let mut to_remove: DryRunRemoveMap = BTreeMap::new();
        to_remove.insert(box_id(2), ());
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(box_id(9), vec![0x99u8; 44]);

        let mut base: Option<crate::store::snapshot::DryRunBase> = None;
        let mut prev_identity: Option<usize> = None;

        for call in 0..3 {
            // Fresh uncached oracle each iteration (its own throwaway prover).
            let snap_oracle = store.committed_snapshot().unwrap().expect("snap oracle");
            let oracle = snap_oracle
                .candidate_dry_run_via_changes_for_test(&[], &to_remove, &to_insert)
                .expect("uncached oracle");

            let snap = store.committed_snapshot().unwrap().expect("snap cached");
            let mut disp = None;
            let got = snap
                .candidate_dry_run_cached_with_changes(
                    &mut base,
                    &[],
                    &to_remove,
                    &to_insert,
                    &mut disp,
                )
                .expect("cached dry-run");

            assert_eq!(oracle.0, got.0, "call {call}: state_root must match oracle");
            assert_eq!(
                oracle.1, got.1,
                "call {call}: proof bytes must match oracle"
            );
            assert_eq!(oracle.2, got.2, "call {call}: tip id must match oracle");

            // call 0 → first time: no base ⇒ Rehydrated; calls 1+ → Hit.
            let expected_disp = if call == 0 {
                BaseDisposition::Rehydrated
            } else {
                BaseDisposition::Hit
            };
            assert_eq!(
                disp,
                Some(expected_disp),
                "call {call}: disposition must be {expected_disp:?}"
            );

            let identity = base
                .as_ref()
                .expect("base present after a successful call")
                .root_identity()
                .expect("hydrated base has a root node");
            if let Some(prev) = prev_identity {
                assert_eq!(
                    prev, identity,
                    "call {call}: same tip must reuse the memoized base (no rehydrate)"
                );
            }
            prev_identity = Some(identity);
        }
    }

    /// Forced mid-apply failure (remove of a never-inserted key) must
    /// hard-drop the base, and the NEXT call must rehydrate a clean base and
    /// return bytes bit-equal to the uncached oracle. Drives the change-map
    /// core directly because a `CheckedTransaction` is unforgeable here.
    #[test]
    fn cached_error_drops_base_then_recovers() {
        let (_dir, store) = genesis_store();
        let mut base: Option<crate::store::snapshot::DryRunBase> = None;

        // Prime the base with a clean successful build so there is a graph to
        // poison.
        let empty_r: DryRunRemoveMap = BTreeMap::new();
        let empty_i: DryRunInsertMap = BTreeMap::new();
        let snap = store.committed_snapshot().unwrap().expect("snap prime");
        snap.candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("prime build");
        assert!(base.is_some(), "base memoized after a clean build");

        // Force an error: remove a key that is not in the committed tree.
        let mut bad_remove: DryRunRemoveMap = BTreeMap::new();
        bad_remove.insert(box_id(0xEE), ());
        let snap = store.committed_snapshot().unwrap().expect("snap err");
        let err = snap
            .candidate_dry_run_cached_with_changes(&mut base, &[], &bad_remove, &empty_i, &mut None)
            .expect_err("removing a missing key must error");
        assert!(
            matches!(err, StateError::CandidateDryRunProverFailed { .. }),
            "expected CandidateDryRunProverFailed, got {err:?}"
        );
        assert!(
            base.is_none(),
            "base must be hard-dropped after a mid-apply error (poison contract)"
        );

        // Recovery: a real change set after the drop rehydrates and matches the
        // uncached oracle byte-for-byte.
        let mut to_insert: DryRunInsertMap = BTreeMap::new();
        to_insert.insert(box_id(7), vec![0x77u8; 40]);
        let snap_oracle = store.committed_snapshot().unwrap().expect("snap oracle");
        let oracle = snap_oracle
            .candidate_dry_run_via_changes_for_test(&[], &empty_r, &to_insert)
            .expect("uncached oracle");
        let snap = store.committed_snapshot().unwrap().expect("snap recover");
        let mut disp_recover = None;
        let got = snap
            .candidate_dry_run_cached_with_changes(
                &mut base,
                &[],
                &empty_r,
                &to_insert,
                &mut disp_recover,
            )
            .expect("recovered cached build");
        assert!(base.is_some(), "base rehydrated after recovery");
        assert_eq!(oracle.0, got.0, "recovered state_root must match oracle");
        assert_eq!(oracle.1, got.1, "recovered proof bytes must match oracle");
        assert_eq!(
            disp_recover,
            Some(BaseDisposition::Rehydrated),
            "recovery after a poison drop must report Rehydrated (no prior base)"
        );
    }

    /// Panic-path of the poison contract: a `PoisonGuard` armed over a
    /// populated base must hard-drop that base when a panic unwinds through
    /// its scope (the exact branch that fires when ops dirty shared `visited`
    /// bits and then something panics before `generate_proof` cleans them).
    /// Drives the real `Drop` impl via `catch_unwind`, mirroring how the
    /// armed guard wraps `apply_change_set_to_prover` in the cached method.
    #[test]
    fn poison_guard_drops_base_on_unwind() {
        let (_dir, store) = genesis_store();
        let snap = store.committed_snapshot().unwrap().expect("snapshot");
        let (tree, tree_height) = snap.hydrate_tree().expect("hydrate base");
        let mut base = Some(super::DryRunBase {
            tip_id: snap.best_full_block_id(),
            state_root: snap.state_root(),
            tree,
            tree_height,
        });
        assert!(base.as_ref().unwrap().root_identity().is_some());

        // Arm the guard over `base`, then panic before disarming — exactly the
        // unwind shape of an op-then-panic-before-proof. The guard's `Drop`
        // must run during unwind and null the base.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = super::PoisonGuard {
                base: Some(&mut base),
            };
            panic!("injected mid-build panic before generate_proof");
        }));
        assert!(res.is_err(), "the injected panic must unwind");
        assert!(
            base.is_none(),
            "PoisonGuard::drop must hard-drop the base on unwind (poison contract)"
        );
    }

    // ----- try_advance_base (incremental base advance) -----
    //
    // All advance tests follow the same oracle discipline: the oracle is a
    // fresh uncached dry-run (full rehydrate) on the post-advance snapshot.
    // The advance path is exercised only via `candidate_dry_run_cached_with_changes`
    // with a stale base; the test detects the advance path by checking the
    // root_identity of the resulting base (see `advanced_base_dry_run_matches_rehydrated_oracle`
    // for the mechanism).
    //
    // Fixture note: `apply_block_unchecked` does NOT store a BlockTransactions
    // section. For advance to work the test must serialise and store the section
    // itself, using `store_block_section` (test-gated).

    // Helper: build a synthetic BlockTransactions section bytes from a header id
    // and a slice of transactions, and return the modifier_id that keys it.
    fn make_and_store_block_transactions_section(
        store: &StateStore,
        header_id: &[u8; 32],
        transactions_root: &[u8; 32],
        transactions: &[ergo_ser::transaction::Transaction],
    ) -> [u8; 32] {
        use ergo_primitives::digest::ModifierId;
        use ergo_primitives::writer::VlqWriter;
        use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
        use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};

        let section_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, header_id, transactions_root);
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes(*header_id),
            transactions: transactions.to_vec(),
        };
        let mut w = VlqWriter::new();
        write_block_transactions(&mut w, &bt).expect("write_block_transactions");
        store
            .store_block_section(&section_id, &w.result())
            .expect("store_block_section");
        section_id
    }

    /// Advance path takes the cache hit on `N+1` after a single-block advance.
    /// Verified by: state_root + proof bytes equal the oracle, AND the base
    /// root_identity after the advance matches the base root_identity on the
    /// subsequent same-tip hit (i.e. the advance installed a reusable base,
    /// not a throwaway one that gets silently rebuilt each time).
    #[test]
    fn advanced_base_dry_run_matches_rehydrated_oracle() {
        use ergo_primitives::digest::ModifierId;
        use ergo_ser::header::serialize_header;

        let (_dir, mut store) = genesis_store();

        // Apply block 1 with no transactions: get tip N.
        let parent_id = ModifierId::from_bytes([0u8; 32]);
        let hdr_n = {
            let mut hdr = ergo_ser::header::Header {
                version: 2,
                parent_id,
                ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                transactions_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                state_root: ergo_primitives::digest::ADDigest::from_bytes([0u8; 33]),
                timestamp: 1_000_001,
                extension_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                n_bits: 16842752,
                height: 1,
                votes: [0u8; 3],
                unparsed_bytes: vec![],
                solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                    pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                    nonce: [0u8; 8],
                },
            };
            hdr.state_root = store.root_digest();
            hdr
        };
        let (hdr_n_bytes, hdr_n_id) = serialize_header(&hdr_n).expect("serialize hdr_n");
        let hdr_n_id_bytes: [u8; 32] = *hdr_n_id.as_bytes();
        store
            .store_header(&hdr_n_id_bytes, &hdr_n_bytes)
            .expect("store hdr_n");
        let expected_n = store.root_digest();
        // Store empty BlockTransactions for block N.
        make_and_store_block_transactions_section(
            &store,
            &hdr_n_id_bytes,
            hdr_n.transactions_root.as_bytes(),
            &[],
        );
        store
            .apply_block_unchecked(1, &hdr_n_id_bytes, &expected_n, &[])
            .expect("apply N");

        // Seed the base at tip N.
        let mut base: Option<crate::store::snapshot::DryRunBase> = None;
        let empty_r: DryRunRemoveMap = BTreeMap::new();
        let empty_i: DryRunInsertMap = BTreeMap::new();
        let snap_n = store.committed_snapshot().unwrap().expect("snap N");
        snap_n
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("seed at N");
        assert_eq!(
            base.as_ref().map(|b| b.tip_id()),
            Some(hdr_n_id_bytes),
            "base keyed to tip N"
        );

        // Apply block N+1 (empty tx set, so AVL state unchanged).
        let hdr_np1 = {
            let mut hdr = ergo_ser::header::Header {
                version: 2,
                parent_id: hdr_n_id,
                ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                transactions_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                state_root: ergo_primitives::digest::ADDigest::from_bytes([0u8; 33]),
                timestamp: 1_000_002,
                extension_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                n_bits: 16842752,
                height: 2,
                votes: [0u8; 3],
                unparsed_bytes: vec![],
                solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                    pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                    nonce: [0u8; 8],
                },
            };
            hdr.state_root = store.root_digest();
            hdr
        };
        let (hdr_np1_bytes, hdr_np1_id) = serialize_header(&hdr_np1).expect("serialize hdr_np1");
        let hdr_np1_id_bytes: [u8; 32] = *hdr_np1_id.as_bytes();
        store
            .store_header(&hdr_np1_id_bytes, &hdr_np1_bytes)
            .expect("store hdr_np1");
        make_and_store_block_transactions_section(
            &store,
            &hdr_np1_id_bytes,
            hdr_np1.transactions_root.as_bytes(),
            &[],
        );
        let expected_np1 = store.root_digest();
        store
            .apply_block_unchecked(2, &hdr_np1_id_bytes, &expected_np1, &[])
            .expect("apply N+1");

        // Now the advance path should kick in: stale base (tip=N) + snapshot at N+1.
        let oracle_snap = store.committed_snapshot().unwrap().expect("snap oracle");
        let oracle = oracle_snap
            .candidate_dry_run_via_changes_for_test(&[], &empty_r, &empty_i)
            .expect("oracle");

        let snap_np1 = store.committed_snapshot().unwrap().expect("snap N+1");
        let mut disp_advance = None;
        let got = snap_np1
            .candidate_dry_run_cached_with_changes(
                &mut base,
                &[],
                &empty_r,
                &empty_i,
                &mut disp_advance,
            )
            .expect("advance path");

        assert_eq!(oracle.0, got.0, "advanced state_root == oracle");
        assert_eq!(oracle.1, got.1, "advanced proof bytes == oracle");
        assert_eq!(oracle.2, got.2, "tip id == oracle");
        assert_eq!(
            disp_advance,
            Some(BaseDisposition::Advanced),
            "single-step advance must report Advanced disposition"
        );
        assert_eq!(
            base.as_ref().map(|b| b.tip_id()),
            Some(hdr_np1_id_bytes),
            "base now keyed to N+1"
        );
        // Advance path installs a reusable base: a second same-tip call reuses
        // it (root_identity stable) and still matches the oracle.
        let identity_after_advance = base
            .as_ref()
            .unwrap()
            .root_identity()
            .expect("base has root");
        let snap_np1b = store.committed_snapshot().unwrap().expect("snap N+1 b");
        let mut disp_hit = None;
        let got2 = snap_np1b
            .candidate_dry_run_cached_with_changes(
                &mut base,
                &[],
                &empty_r,
                &empty_i,
                &mut disp_hit,
            )
            .expect("second hit");
        assert_eq!(got.0, got2.0, "second hit state_root stable");
        assert_eq!(got.1, got2.1, "second hit proof stable");
        assert_eq!(
            disp_hit,
            Some(BaseDisposition::Hit),
            "second same-tip build must report Hit after advance"
        );
        let identity_second = base.as_ref().unwrap().root_identity().unwrap();
        assert_eq!(
            identity_after_advance, identity_second,
            "same base reused for second hit (no silent rehydrate)"
        );
    }

    /// Two consecutive dry-runs on the advanced base must both match the oracle
    /// (flag-pristine regression: dirty is_new/visited would corrupt the second run).
    #[test]
    fn advanced_base_second_dry_run_still_matches_oracle() {
        use ergo_primitives::digest::ModifierId;
        use ergo_ser::header::serialize_header;

        let (_dir, mut store) = genesis_store();

        // Block N: empty txs.
        let hdr_n = ergo_ser::header::Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0u8; 32]),
            ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            transactions_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            state_root: store.root_digest(),
            timestamp: 2_000_001,
            extension_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 1,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let (hdr_n_bytes, hdr_n_id) = serialize_header(&hdr_n).unwrap();
        let hdr_n_id_b: [u8; 32] = *hdr_n_id.as_bytes();
        store.store_header(&hdr_n_id_b, &hdr_n_bytes).unwrap();
        make_and_store_block_transactions_section(
            &store,
            &hdr_n_id_b,
            hdr_n.transactions_root.as_bytes(),
            &[],
        );
        store
            .apply_block_unchecked(1, &hdr_n_id_b, &hdr_n.state_root, &[])
            .unwrap();

        // Seed base at N.
        let mut base: Option<crate::store::snapshot::DryRunBase> = None;
        let empty_r: DryRunRemoveMap = BTreeMap::new();
        let empty_i: DryRunInsertMap = BTreeMap::new();
        let snap_n = store.committed_snapshot().unwrap().unwrap();
        snap_n
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .unwrap();

        // Block N+1: also empty.
        let hdr_np1 = ergo_ser::header::Header {
            version: 2,
            parent_id: hdr_n_id,
            ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            transactions_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            state_root: store.root_digest(),
            timestamp: 2_000_002,
            extension_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 2,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let (hdr_np1_bytes, hdr_np1_id) = serialize_header(&hdr_np1).unwrap();
        let hdr_np1_id_b: [u8; 32] = *hdr_np1_id.as_bytes();
        store.store_header(&hdr_np1_id_b, &hdr_np1_bytes).unwrap();
        make_and_store_block_transactions_section(
            &store,
            &hdr_np1_id_b,
            hdr_np1.transactions_root.as_bytes(),
            &[],
        );
        store
            .apply_block_unchecked(2, &hdr_np1_id_b, &hdr_np1.state_root, &[])
            .unwrap();

        // Advance path: stale base at N, snapshot at N+1.
        let snap_np1 = store.committed_snapshot().unwrap().unwrap();
        let first = snap_np1
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("first run on advanced base");

        // Oracle for comparison (fresh rehydrate each time).
        let oracle_snap = store.committed_snapshot().unwrap().unwrap();
        let oracle = oracle_snap
            .candidate_dry_run_via_changes_for_test(&[], &empty_r, &empty_i)
            .expect("oracle");

        // Second run on same advanced base — must not corrupt visited flags.
        let snap_np1b = store.committed_snapshot().unwrap().unwrap();
        let second = snap_np1b
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("second run on advanced base");

        assert_eq!(oracle.0, first.0, "first run state_root == oracle");
        assert_eq!(oracle.1, first.1, "first run proof bytes == oracle");
        assert_eq!(oracle.0, second.0, "second run state_root == oracle");
        assert_eq!(oracle.1, second.1, "second run proof bytes == oracle");
    }

    /// With a 2-block jump (base at N, snapshot at N+2), the advance gate
    /// rejects (parent_id mismatch) and falls back to full rehydrate.
    /// The result must equal the fresh-rehydrate oracle.
    #[test]
    fn advance_rejected_on_multi_block_jump() {
        use ergo_primitives::digest::ModifierId;
        use ergo_ser::header::serialize_header;

        let (_dir, mut store) = genesis_store();
        let empty_r: DryRunRemoveMap = BTreeMap::new();
        let empty_i: DryRunInsertMap = BTreeMap::new();

        // Apply blocks 1 and 2; store empty BT sections for both.
        let mut parent = ModifierId::from_bytes([0u8; 32]);
        for (h, ts) in [(1u32, 3_000_001u64), (2, 3_000_002)] {
            let hdr = ergo_ser::header::Header {
                version: 2,
                parent_id: parent,
                ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                transactions_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                state_root: store.root_digest(),
                timestamp: ts,
                extension_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                n_bits: 16842752,
                height: h,
                votes: [0u8; 3],
                unparsed_bytes: vec![],
                solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                    pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                    nonce: [0u8; 8],
                },
            };
            let (bytes, id) = serialize_header(&hdr).unwrap();
            let id_b: [u8; 32] = *id.as_bytes();
            store.store_header(&id_b, &bytes).unwrap();
            make_and_store_block_transactions_section(
                &store,
                &id_b,
                hdr.transactions_root.as_bytes(),
                &[],
            );
            store
                .apply_block_unchecked(h, &id_b, &hdr.state_root, &[])
                .unwrap();
            parent = id;
        }

        // Seed base at N=1 (BEFORE block 2 was applied, so two blocks behind).
        // To get the base at height 1, we need to snapshot before block 2 was
        // applied. But the store is already at height 2. We cannot go back.
        // Instead: prime the base with a WRONG tip_id (different from any block
        // in the chain at height N+1 from the snapshot's perspective), which
        // forces the advance gate to reject on parent-id mismatch.
        //
        // Specifically: the snapshot is now at height 2. We prime the base with
        // a fake tip_id that is not the height-1 block id, so the height-2
        // header's parent_id won't match.
        // Manually construct a base with a fake tip_id (all 0xFF) so the
        // advance gate rejects on parent-id mismatch and falls back to rehydrate.
        let snap_for_fake = store.committed_snapshot().unwrap().unwrap();
        let (fake_tree, fake_tree_height) =
            snap_for_fake.hydrate_tree().expect("hydrate for fake base");
        let mut base: Option<crate::store::snapshot::DryRunBase> = Some(super::DryRunBase {
            tip_id: [0xFFu8; 32],
            state_root: snap_for_fake.state_root(),
            tree: fake_tree,
            tree_height: fake_tree_height,
        });

        let oracle_snap = store.committed_snapshot().unwrap().unwrap();
        let oracle = oracle_snap
            .candidate_dry_run_via_changes_for_test(&[], &empty_r, &empty_i)
            .expect("oracle");

        let snap = store.committed_snapshot().unwrap().unwrap();
        let got = snap
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("fallback after multi-block jump");

        assert_eq!(
            oracle.0, got.0,
            "multi-block jump fallback: state_root == oracle"
        );
        assert_eq!(
            oracle.1, got.1,
            "multi-block jump fallback: proof bytes == oracle"
        );
        assert_eq!(
            oracle.2, got.2,
            "multi-block jump fallback: tip id == oracle"
        );
        // Base was rebuilt by fallback to match current tip.
        assert_eq!(
            base.as_ref().map(|b| b.tip_id()),
            Some(oracle.2),
            "base keyed to current tip after fallback"
        );
    }

    /// With a base at an equal-height sibling tip (reorg scenario), the
    /// advance gate rejects (parent_id mismatch) and falls back to full
    /// rehydrate. Result equals oracle. Uses same cross-store mechanism as
    /// `cached_reorg_same_height_rebuilds`.
    #[test]
    fn advance_rejected_on_sibling_reorg() {
        use ergo_primitives::digest::ModifierId;
        use ergo_ser::header::serialize_header;

        // Store A: linear chain to height 2.
        let dir_a = tempfile::tempdir().unwrap();
        let mut store_a = StateStore::open(dir_a.path().join("a.redb").as_path()).unwrap();
        {
            let boxes: Vec<([u8; 32], Vec<u8>)> = vec![{
                let mut id = [0u8; 32];
                id[31] = 1;
                (id, vec![0xAAu8; 32])
            }];
            store_a.initialize_genesis(&boxes).unwrap();
        }

        let mut parent = ModifierId::from_bytes([0u8; 32]);
        for (h, ts) in [(1u32, 5_000_001u64), (2, 5_000_002)] {
            let hdr = ergo_ser::header::Header {
                version: 2,
                parent_id: parent,
                ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                transactions_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                state_root: store_a.root_digest(),
                timestamp: ts,
                extension_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                n_bits: 16842752,
                height: h,
                votes: [0u8; 3],
                unparsed_bytes: vec![],
                solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                    pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                    nonce: [0u8; 8],
                },
            };
            let (bytes, id) = serialize_header(&hdr).unwrap();
            let id_b: [u8; 32] = *id.as_bytes();
            store_a.store_header(&id_b, &bytes).unwrap();
            make_and_store_block_transactions_section(
                &store_a,
                &id_b,
                hdr.transactions_root.as_bytes(),
                &[],
            );
            store_a
                .apply_block_unchecked(h, &id_b, &hdr.state_root, &[])
                .unwrap();
            parent = id;
        }
        let tip_a = store_a.chain_state().best_full_block_id;

        // Store B: divergent chain (different timestamps) to height 2.
        let dir_b = tempfile::tempdir().unwrap();
        let mut store_b = StateStore::open(dir_b.path().join("b.redb").as_path()).unwrap();
        {
            let boxes: Vec<([u8; 32], Vec<u8>)> = vec![{
                let mut id = [0u8; 32];
                id[31] = 1;
                (id, vec![0xAAu8; 32])
            }];
            store_b.initialize_genesis(&boxes).unwrap();
        }
        let mut parent = ModifierId::from_bytes([0u8; 32]);
        for (h, ts) in [(1u32, 9_000_001u64), (2, 9_000_002)] {
            let hdr = ergo_ser::header::Header {
                version: 2,
                parent_id: parent,
                ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                transactions_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                state_root: store_b.root_digest(),
                timestamp: ts,
                extension_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
                n_bits: 16842752,
                height: h,
                votes: [0u8; 3],
                unparsed_bytes: vec![],
                solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                    pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                    nonce: [0u8; 8],
                },
            };
            let (bytes, id) = serialize_header(&hdr).unwrap();
            let id_b: [u8; 32] = *id.as_bytes();
            store_b.store_header(&id_b, &bytes).unwrap();
            make_and_store_block_transactions_section(
                &store_b,
                &id_b,
                hdr.transactions_root.as_bytes(),
                &[],
            );
            store_b
                .apply_block_unchecked(h, &id_b, &hdr.state_root, &[])
                .unwrap();
            parent = id;
        }
        let tip_b = store_b.chain_state().best_full_block_id;
        assert_ne!(
            tip_a, tip_b,
            "two divergent chains must have different tip ids"
        );

        // Prime a base from store_a's tip.
        let mut base: Option<crate::store::snapshot::DryRunBase> = None;
        let empty_r: DryRunRemoveMap = BTreeMap::new();
        let empty_i: DryRunInsertMap = BTreeMap::new();
        let snap_a = store_a.committed_snapshot().unwrap().unwrap();
        snap_a
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("prime on A");
        assert_eq!(base.as_ref().map(|b| b.tip_id()), Some(tip_a));

        // Now use store_b's snapshot: tip_b != tip_a → advance gate rejects (not
        // a descendant), falls back to full rehydrate.
        let oracle_b_snap = store_b.committed_snapshot().unwrap().unwrap();
        let oracle_b = oracle_b_snap
            .candidate_dry_run_via_changes_for_test(&[], &empty_r, &empty_i)
            .expect("oracle B");

        let snap_b = store_b.committed_snapshot().unwrap().unwrap();
        let got = snap_b
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("fallback on sibling reorg");

        assert_eq!(oracle_b.0, got.0, "sibling reorg: state_root == oracle B");
        assert_eq!(oracle_b.1, got.1, "sibling reorg: proof bytes == oracle B");
        assert_eq!(oracle_b.2, got.2, "sibling reorg: tip id == oracle B");
        assert_eq!(
            base.as_ref().map(|b| b.tip_id()),
            Some(tip_b),
            "base rekeyed to B's tip after fallback"
        );
    }

    /// When N+1's BlockTransactions section is absent, the advance path returns
    /// Err and falls back to full rehydrate. Result equals oracle.
    #[test]
    fn advance_rejected_on_missing_tx_section() {
        use ergo_primitives::digest::ModifierId;
        use ergo_ser::header::serialize_header;

        let (_dir, mut store) = genesis_store();
        let empty_r: DryRunRemoveMap = BTreeMap::new();
        let empty_i: DryRunInsertMap = BTreeMap::new();

        // Block N: no BlockTransactions section stored.
        let hdr_n = ergo_ser::header::Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0u8; 32]),
            ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            transactions_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            state_root: store.root_digest(),
            timestamp: 4_000_001,
            extension_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 1,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let (hdr_n_bytes, hdr_n_id) = serialize_header(&hdr_n).unwrap();
        let hdr_n_id_b: [u8; 32] = *hdr_n_id.as_bytes();
        store.store_header(&hdr_n_id_b, &hdr_n_bytes).unwrap();
        store
            .apply_block_unchecked(1, &hdr_n_id_b, &hdr_n.state_root, &[])
            .unwrap();

        // Seed base at N.
        let mut base: Option<crate::store::snapshot::DryRunBase> = None;
        let snap_n = store.committed_snapshot().unwrap().unwrap();
        snap_n
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .unwrap();

        // Block N+1: header stored but NO BlockTransactions section.
        let hdr_np1 = ergo_ser::header::Header {
            version: 2,
            parent_id: hdr_n_id,
            ad_proofs_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            transactions_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            state_root: store.root_digest(),
            timestamp: 4_000_002,
            extension_root: ergo_primitives::digest::Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 2,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let (hdr_np1_bytes, hdr_np1_id) = serialize_header(&hdr_np1).unwrap();
        let hdr_np1_id_b: [u8; 32] = *hdr_np1_id.as_bytes();
        store.store_header(&hdr_np1_id_b, &hdr_np1_bytes).unwrap();
        // Intentionally NOT storing the BlockTransactions section for N+1.
        store
            .apply_block_unchecked(2, &hdr_np1_id_b, &hdr_np1.state_root, &[])
            .unwrap();

        let oracle_snap = store.committed_snapshot().unwrap().unwrap();
        let oracle = oracle_snap
            .candidate_dry_run_via_changes_for_test(&[], &empty_r, &empty_i)
            .expect("oracle");

        let snap_np1 = store.committed_snapshot().unwrap().unwrap();
        let got = snap_np1
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("fallback when BT section absent");

        assert_eq!(oracle.0, got.0, "missing section: state_root == oracle");
        assert_eq!(oracle.1, got.1, "missing section: proof bytes == oracle");
        assert_eq!(oracle.2, got.2, "missing section: tip id == oracle");
    }

    /// A mid-advance prover error (parse succeeds but the change set removes a
    /// key absent from the base tree) must drop the base; the next call must
    /// recover by rehydrating and producing bytes equal to the oracle.
    ///
    /// To trigger this: we build block N+1 with a BlockTransactions section that
    /// claims to remove box_id(0xEE) — a key never inserted — so the advance
    /// prover fails after the op, leaving the slot None. The subsequent call with
    /// an empty change set must rehydrate and match the oracle.
    #[test]
    fn advance_failure_drops_base_then_recovers() {
        use ergo_primitives::digest::{Digest32, ModifierId};
        use ergo_ser::ergo_box::ErgoBoxCandidate;
        use ergo_ser::ergo_tree::ErgoTree;
        use ergo_ser::header::serialize_header;
        use ergo_ser::input::{ContextExtension, Input, SpendingProof};
        use ergo_ser::opcode::Expr;
        use ergo_ser::register::AdditionalRegisters;
        use ergo_ser::sigma_type::SigmaType;
        use ergo_ser::sigma_value::SigmaValue;
        use ergo_ser::transaction::Transaction;

        let (_dir, mut store) = genesis_store();
        let empty_r: DryRunRemoveMap = BTreeMap::new();
        let empty_i: DryRunInsertMap = BTreeMap::new();

        // Block N: no transactions.
        let hdr_n = ergo_ser::header::Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0u8; 32]),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: store.root_digest(),
            timestamp: 6_000_001,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 1,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let (hdr_n_bytes, hdr_n_id) = serialize_header(&hdr_n).unwrap();
        let hdr_n_id_b: [u8; 32] = *hdr_n_id.as_bytes();
        store.store_header(&hdr_n_id_b, &hdr_n_bytes).unwrap();
        make_and_store_block_transactions_section(
            &store,
            &hdr_n_id_b,
            hdr_n.transactions_root.as_bytes(),
            &[],
        );
        store
            .apply_block_unchecked(1, &hdr_n_id_b, &hdr_n.state_root, &[])
            .unwrap();

        // Seed base at N.
        let mut base: Option<crate::store::snapshot::DryRunBase> = None;
        let snap_n = store.committed_snapshot().unwrap().unwrap();
        snap_n
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .unwrap();
        assert!(base.is_some(), "base seeded at N");

        // Block N+1: also apply without UTXO changes so the state root stays
        // the same. But store a BlockTransactions section that lies about removing
        // box_id(0xEE) — a key absent from the AVL tree — so the advance prover
        // fails. We craft the section manually with a synthetic Transaction that
        // inputs box_id(0xEE).
        let bad_input_id = Digest32::from_bytes(box_id(0xEE));
        let fake_tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        };
        let fake_output = ErgoBoxCandidate::new(
            1_000_000,
            fake_tree,
            2,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        let bad_tx = Transaction {
            inputs: vec![Input {
                box_id: bad_input_id,
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![fake_output],
        };
        let hdr_np1 = ergo_ser::header::Header {
            version: 2,
            parent_id: hdr_n_id,
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: store.root_digest(), // unchanged (no real UTXO apply)
            timestamp: 6_000_002,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 2,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let (hdr_np1_bytes, hdr_np1_id) = serialize_header(&hdr_np1).unwrap();
        let hdr_np1_id_b: [u8; 32] = *hdr_np1_id.as_bytes();
        store.store_header(&hdr_np1_id_b, &hdr_np1_bytes).unwrap();
        // Store a BlockTransactions section that references the bad transaction.
        // This will be decoded by try_advance_base and will fail the prover step.
        make_and_store_block_transactions_section(
            &store,
            &hdr_np1_id_b,
            hdr_np1.transactions_root.as_bytes(),
            &[bad_tx],
        );
        // Apply N+1 with NO actual UTXO changes (empty slice) so state root matches.
        store
            .apply_block_unchecked(2, &hdr_np1_id_b, &hdr_np1.state_root, &[])
            .unwrap();

        // The advance path decodes the section, sees a remove of 0xEE (absent),
        // prover fails → base dropped (slot becomes None or new), then recovers.
        let snap_np1 = store.committed_snapshot().unwrap().unwrap();
        let mut disp_fallback = None;
        let got = snap_np1
            .candidate_dry_run_cached_with_changes(
                &mut base,
                &[],
                &empty_r,
                &empty_i,
                &mut disp_fallback,
            )
            .expect("recovery after advance prover failure");

        let oracle_snap = store.committed_snapshot().unwrap().unwrap();
        let oracle = oracle_snap
            .candidate_dry_run_via_changes_for_test(&[], &empty_r, &empty_i)
            .expect("oracle after recovery");

        assert_eq!(oracle.0, got.0, "recovery state_root == oracle");
        assert_eq!(oracle.1, got.1, "recovery proof bytes == oracle");
        assert!(base.is_some(), "base re-established after recovery");
        assert_eq!(
            disp_fallback,
            Some(BaseDisposition::RehydratedAfterFailedAdvance),
            "advance prover failure must report RehydratedAfterFailedAdvance"
        );
    }

    /// Non-empty block advance: apply block N+1 with a real transaction
    /// (spends genesis box_id(1), creates box_id(10)). The stored
    /// BlockTransactions section carries that transaction; `try_advance_base`
    /// replays it through the cached prover, verifies the resulting digest
    /// equals the committed state root, and returns `Advanced`.
    ///
    /// This pins: tx-id recomputation, create+spend UTXO netting, and the
    /// replay path on a non-empty section — the risk surface Codex identified
    /// as unpinned by the empty-block-only advance tests.
    #[test]
    fn advanced_base_non_empty_block_mutations_match_oracle() {
        use ergo_primitives::digest::{Digest32, ModifierId};
        use ergo_ser::ergo_box::ErgoBoxCandidate;
        use ergo_ser::ergo_tree::ErgoTree;
        use ergo_ser::header::serialize_header;
        use ergo_ser::input::{ContextExtension, Input, SpendingProof};
        use ergo_ser::opcode::Expr;
        use ergo_ser::register::AdditionalRegisters;
        use ergo_ser::sigma_type::SigmaType;
        use ergo_ser::sigma_value::SigmaValue;
        use ergo_ser::transaction::Transaction;

        let (_dir, mut store) = genesis_store();
        // genesis_store seeds box_id(1), box_id(2), box_id(3).
        let empty_r: DryRunRemoveMap = BTreeMap::new();
        let empty_i: DryRunInsertMap = BTreeMap::new();

        // A minimal ErgoTree that always evaluates to true (used as output script).
        let true_tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        };

        // Block N (height 1): spend box_id(1), create box_id(10).
        // The transaction is stored in both the unchecked apply AND the
        // BlockTransactions section so that `try_advance_base` can replay it.
        let spend_tx = Transaction {
            inputs: vec![Input {
                box_id: Digest32::from_bytes(box_id(1)),
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate::new(
                1_000_000,
                true_tree.clone(),
                1,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap()],
        };

        // Apply block N with the UTXO transaction so the state root captures
        // the mutation.
        let hdr_n = ergo_ser::header::Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0u8; 32]),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: store.root_digest(), // will be updated after apply
            timestamp: 7_000_001,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 1,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        // Compute what the state root will be after applying the tx.
        let (to_remove_n, to_insert_n) =
            StateStore::build_utxo_changes_raw(&[&spend_tx]).expect("build utxo changes N");
        let root_after_n = {
            let snap = store.committed_snapshot().unwrap().unwrap();
            let mut prover = snap.hydrate_prover().expect("hydrate for root_after_n");
            let (digest, _) = crate::store::dry_run::apply_change_set_to_prover(
                &mut prover,
                &[],
                &to_remove_n,
                &to_insert_n,
            )
            .expect("apply N preview");
            digest
        };
        let (hdr_n_bytes, hdr_n_id) = serialize_header(&hdr_n).expect("serialize hdr_n");
        let hdr_n_id_b: [u8; 32] = *hdr_n_id.as_bytes();
        store.store_header(&hdr_n_id_b, &hdr_n_bytes).unwrap();
        make_and_store_block_transactions_section(
            &store,
            &hdr_n_id_b,
            hdr_n.transactions_root.as_bytes(),
            std::slice::from_ref(&spend_tx),
        );
        store
            .apply_block_unchecked(1, &hdr_n_id_b, &root_after_n, &[spend_tx])
            .expect("apply N with UTXO mutation");

        // Seed the base at tip N.
        let mut base: Option<crate::store::snapshot::DryRunBase> = None;
        let snap_n = store.committed_snapshot().unwrap().expect("snap N");
        snap_n
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("seed base at N");
        assert_eq!(
            base.as_ref().map(|b| b.tip_id()),
            Some(hdr_n_id_b),
            "base keyed to tip N"
        );

        // Block N+1 (height 2): empty transactions.
        let hdr_np1 = ergo_ser::header::Header {
            version: 2,
            parent_id: hdr_n_id,
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: store.root_digest(), // unchanged (no new UTXO changes)
            timestamp: 7_000_002,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 2,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let root_np1 = store.root_digest();
        let (hdr_np1_bytes, hdr_np1_id) = serialize_header(&hdr_np1).expect("serialize hdr_np1");
        let hdr_np1_id_b: [u8; 32] = *hdr_np1_id.as_bytes();
        store.store_header(&hdr_np1_id_b, &hdr_np1_bytes).unwrap();
        make_and_store_block_transactions_section(
            &store,
            &hdr_np1_id_b,
            hdr_np1.transactions_root.as_bytes(),
            &[],
        );
        store
            .apply_block_unchecked(2, &hdr_np1_id_b, &root_np1, &[])
            .expect("apply N+1 empty");

        // Oracle: fresh uncached dry-run at N+1.
        let oracle_snap = store.committed_snapshot().unwrap().expect("oracle snap");
        let oracle = oracle_snap
            .candidate_dry_run_via_changes_for_test(&[], &empty_r, &empty_i)
            .expect("oracle");

        // Advance path: stale base at N (contains N's post-mutation tree),
        // snapshot at N+1. Block N+1 has empty BT section, so the advance
        // replays no UTXO changes and leaves the digest unchanged — matching
        // root_np1 (the committed state root at N+1). Must report Advanced.
        let snap_np1 = store.committed_snapshot().unwrap().expect("snap N+1");
        let mut disp = None;
        let got = snap_np1
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut disp)
            .expect("advance path at N+1");

        assert_eq!(
            oracle.0, got.0,
            "non-empty-parent advance: state_root == oracle"
        );
        assert_eq!(
            oracle.1, got.1,
            "non-empty-parent advance: proof bytes == oracle"
        );
        assert_eq!(
            oracle.2, got.2,
            "non-empty-parent advance: tip id == oracle"
        );
        assert_eq!(
            disp,
            Some(BaseDisposition::Advanced),
            "single-step advance after non-empty-block parent must report Advanced"
        );
        assert_eq!(
            base.as_ref().map(|b| b.tip_id()),
            Some(hdr_np1_id_b),
            "base rekeyed to N+1 after advance"
        );
        // Reuse the advanced base: a second same-tip call must report Hit and
        // still match the oracle. This pins that the advanced base (built from
        // a post-mutation tree) is correctly pristine for reuse — the same
        // invariant as `advanced_base_second_dry_run_still_matches_oracle` but
        // now after a non-empty-block advance, not an empty one.
        let snap_np1_b = store.committed_snapshot().unwrap().expect("snap N+1 b");
        let mut disp_hit = None;
        let got2 = snap_np1_b
            .candidate_dry_run_cached_with_changes(
                &mut base,
                &[],
                &empty_r,
                &empty_i,
                &mut disp_hit,
            )
            .expect("second same-tip hit after non-empty advance");
        assert_eq!(
            oracle.0, got2.0,
            "second hit state_root still matches oracle"
        );
        assert_eq!(
            oracle.1, got2.1,
            "second hit proof bytes still match oracle"
        );
        assert_eq!(
            disp_hit,
            Some(BaseDisposition::Hit),
            "second same-tip call after non-empty advance must report Hit"
        );
    }

    /// Digest-mismatch fallback: store a BlockTransactions section for block
    /// N+1 that claims to INSERT a new box (box_id(20)), but apply block N+1
    /// with no real UTXO changes (so the committed state root does NOT include
    /// the inserted box). When `try_advance_base` replays the insert its
    /// computed digest won't match the committed `state_root`, triggering the
    /// hard `DigestMismatch` guard at snapshot.rs:514 and falling back to full
    /// rehydrate with `RehydratedAfterFailedAdvance`.
    #[test]
    fn advance_digest_mismatch_falls_back_to_rehydrate() {
        use ergo_primitives::digest::{Digest32, ModifierId};
        use ergo_ser::ergo_box::ErgoBoxCandidate;
        use ergo_ser::ergo_tree::ErgoTree;
        use ergo_ser::header::serialize_header;
        use ergo_ser::input::{ContextExtension, Input, SpendingProof};
        use ergo_ser::opcode::Expr;
        use ergo_ser::register::AdditionalRegisters;
        use ergo_ser::sigma_type::SigmaType;
        use ergo_ser::sigma_value::SigmaValue;
        use ergo_ser::transaction::Transaction;

        let (_dir, mut store) = genesis_store();
        let empty_r: DryRunRemoveMap = BTreeMap::new();
        let empty_i: DryRunInsertMap = BTreeMap::new();

        let true_tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        };

        // Block N: empty transactions.
        let hdr_n = ergo_ser::header::Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0u8; 32]),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: store.root_digest(),
            timestamp: 8_000_001,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 1,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let (hdr_n_bytes, hdr_n_id) = serialize_header(&hdr_n).unwrap();
        let hdr_n_id_b: [u8; 32] = *hdr_n_id.as_bytes();
        store.store_header(&hdr_n_id_b, &hdr_n_bytes).unwrap();
        make_and_store_block_transactions_section(
            &store,
            &hdr_n_id_b,
            hdr_n.transactions_root.as_bytes(),
            &[],
        );
        store
            .apply_block_unchecked(1, &hdr_n_id_b, &hdr_n.state_root, &[])
            .unwrap();

        // Seed base at N.
        let mut base: Option<crate::store::snapshot::DryRunBase> = None;
        let snap_n = store.committed_snapshot().unwrap().unwrap();
        snap_n
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut None)
            .expect("seed base at N");
        assert!(base.is_some(), "base seeded at N");

        // Block N+1: apply WITHOUT UTXO changes (state root unchanged).
        // But store a BlockTransactions section that claims to SPEND box_id(1)
        // and INSERT box_id(20) — a transaction that was never actually applied.
        // `try_advance_base` replays the insert, produces a different digest
        // than the committed state root, and hits `DigestMismatch`.
        let lying_tx = Transaction {
            inputs: vec![Input {
                box_id: Digest32::from_bytes(box_id(1)),
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate::new(
                999_000,
                true_tree,
                2,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap()],
        };
        let root_n = store.root_digest(); // unchanged (no actual UTXO apply at N+1)
        let hdr_np1 = ergo_ser::header::Header {
            version: 2,
            parent_id: hdr_n_id,
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: root_n,
            timestamp: 8_000_002,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 16842752,
            height: 2,
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: ergo_ser::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        let (hdr_np1_bytes, hdr_np1_id) = serialize_header(&hdr_np1).unwrap();
        let hdr_np1_id_b: [u8; 32] = *hdr_np1_id.as_bytes();
        store.store_header(&hdr_np1_id_b, &hdr_np1_bytes).unwrap();
        // Store the LYING section (contains the unapplied transaction).
        make_and_store_block_transactions_section(
            &store,
            &hdr_np1_id_b,
            hdr_np1.transactions_root.as_bytes(),
            &[lying_tx],
        );
        // Apply block N+1 with NO transactions (no real UTXO mutation).
        store
            .apply_block_unchecked(2, &hdr_np1_id_b, &root_n, &[])
            .expect("apply N+1 without UTXO changes");

        // Oracle: fresh uncached dry-run at N+1.
        let oracle_snap = store.committed_snapshot().unwrap().unwrap();
        let oracle = oracle_snap
            .candidate_dry_run_via_changes_for_test(&[], &empty_r, &empty_i)
            .expect("oracle");

        // Advance path: the lying BT section causes a digest mismatch in
        // try_advance_base. Must fall back to full rehydrate.
        let snap_np1 = store.committed_snapshot().unwrap().unwrap();
        let mut disp = None;
        let got = snap_np1
            .candidate_dry_run_cached_with_changes(&mut base, &[], &empty_r, &empty_i, &mut disp)
            .expect("fallback after digest mismatch");

        assert_eq!(
            oracle.0, got.0,
            "digest-mismatch fallback: state_root == oracle"
        );
        assert_eq!(
            oracle.1, got.1,
            "digest-mismatch fallback: proof bytes == oracle"
        );
        assert_eq!(
            disp,
            Some(BaseDisposition::RehydratedAfterFailedAdvance),
            "digest mismatch in try_advance_base must report RehydratedAfterFailedAdvance"
        );
        assert!(
            base.is_some(),
            "base re-established after digest-mismatch fallback"
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
