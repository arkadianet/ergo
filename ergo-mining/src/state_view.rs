//! `CandidateStateView`: the read surface the candidate builder needs,
//! abstracted over its committed-state source.
//!
//! `generate_candidate` reads several consensus-bearing inputs — the
//! best-full tip, the parent header, the last-10 applied-header window,
//! the active params + validation settings, epoch headers (difficulty
//! retarget), the parent extension + block-transactions sections
//! (interlinks + emission box), and the AVL+ dry-run. On-loop those come
//! from the live `StateStore`; off-loop (the regeneration engine) they
//! must come from a single `CommittedSnapshot` read transaction so the
//! whole build is one consistent committed view (mixing per-call
//! transactions could splice inputs across a commit boundary and diverge
//! from the on-loop build).
//!
//! This trait is the seam. The `StateStore` impl delegates verbatim to
//! the existing inherent methods, so the on-loop build is byte-for-byte
//! unchanged; the `CommittedSnapshot` impl serves every read from its one
//! held transaction. Each read has already been proven byte-identical
//! between the two (see `ergo-state` `committed_snapshot_parity` +
//! the in-crate snapshot parity tests), so for the same committed tip the
//! two views produce the same candidate.

use std::cell::{Cell, RefCell};

use ergo_primitives::digest::ADDigest;
use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_ser::transaction::write_transaction;
use ergo_state::store::{BaseDisposition, CommittedSnapshot, DryRunBase, StateError, StateStore};
use ergo_validation::{
    ActiveProtocolParameters, CheckedTransaction, ErgoValidationSettings, UtxoView,
};

/// One consistent committed view of the chain + authenticated state, as
/// the candidate builder consumes it. Implemented for the live
/// `StateStore` (on-loop) and for `CommittedSnapshot` (off-loop engine).
///
/// All methods must reflect ONE committed view; the `CommittedSnapshot`
/// impl guarantees this by sourcing every read from a single redb read
/// transaction.
///
/// Requires [`UtxoView`] (box resolution): the candidate builder seeds its
/// in-block overlay with the view as the committed base UTXO set, so the
/// snapshot's `get_box` must read from the same held transaction as the
/// rest of the build.
pub trait CandidateStateView: UtxoView {
    /// Persisted parent emission identity; outer None means unavailable history.
    fn emission_identity(&self, tip: &[u8; 32]) -> Result<Option<Option<Digest32>>, StateError>;
    /// Best fully-applied block id — the candidate's parent.
    fn best_full_block_id(&self) -> [u8; 32];
    /// Height of the best fully-applied block.
    fn best_full_block_height(&self) -> u32;
    /// Raw serialized header bytes by id (`None` if absent).
    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError>;
    /// Canonical header-chain id at `height` (`None` if absent).
    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError>;
    /// Serialized block-section bytes by modifier id (`None` if absent).
    fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError>;
    /// Last 10 applied-chain headers, tip-first.
    fn last_applied_chain_window_10(&self) -> Result<[Header; 10], StateError>;
    /// Active protocol params + cumulative validation settings at the tip.
    fn tip_snapshot_params(
        &self,
    ) -> Result<(ActiveProtocolParameters, ErgoValidationSettings), StateError>;
    /// Speculative AVL+ apply of `checked`, returning
    /// `(new_state_root, ad_proof_bytes, snapshot_tip_id)`.
    fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError>;
    /// Whether the Mode 2 (UTXO-snapshot) first-epoch trust sentinel is armed in
    /// this committed view. While armed, the cumulative validation settings the
    /// view reports are still the launch defaults (not the real pre-snapshot
    /// cumulative), so an epoch-boundary candidate built here would serialize a
    /// `0x02` block peers reject on `exMatchValidationSettings`. The builder
    /// refuses boundary mining while this is `true`.
    fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError>;
}

// On-loop: verbatim delegation to the existing inherent methods, so the
// live candidate build is byte-for-byte unchanged. Each body is
// fully-qualified to the inherent method to rule out any trait-vs-inherent
// resolution ambiguity (and accidental self-recursion).
impl CandidateStateView for StateStore {
    fn emission_identity(&self, tip: &[u8; 32]) -> Result<Option<Option<Digest32>>, StateError> {
        StateStore::emission_identity(self, tip)
    }
    fn best_full_block_id(&self) -> [u8; 32] {
        StateStore::chain_state(self).best_full_block_id
    }
    fn best_full_block_height(&self) -> u32 {
        StateStore::chain_state(self).best_full_block_height
    }
    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        StateStore::get_header(self, id)
    }
    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        StateStore::get_header_id_at_height(self, height)
    }
    fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        StateStore::get_block_section(self, modifier_id)
    }
    fn last_applied_chain_window_10(&self) -> Result<[Header; 10], StateError> {
        StateStore::last_applied_chain_window_10(self)
    }
    fn tip_snapshot_params(
        &self,
    ) -> Result<(ActiveProtocolParameters, ErgoValidationSettings), StateError> {
        Ok(StateStore::tip_snapshot_params(self))
    }
    fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        StateStore::candidate_dry_run(self, checked)
    }
    fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError> {
        Ok(StateStore::is_mode2_trust_first_epoch_armed(self))
    }
}

// Off-loop: every read served from the snapshot's one held transaction.
impl CandidateStateView for CommittedSnapshot {
    fn emission_identity(&self, tip: &[u8; 32]) -> Result<Option<Option<Digest32>>, StateError> {
        CommittedSnapshot::emission_identity(self, tip)
    }
    fn best_full_block_id(&self) -> [u8; 32] {
        CommittedSnapshot::best_full_block_id(self)
    }
    fn best_full_block_height(&self) -> u32 {
        CommittedSnapshot::best_full_block_height(self)
    }
    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::get_header_bytes(self, id)
    }
    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        CommittedSnapshot::header_id_at_height(self, height)
    }
    fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::block_section(self, modifier_id)
    }
    fn last_applied_chain_window_10(&self) -> Result<[Header; 10], StateError> {
        CommittedSnapshot::last_headers_window(self)
    }
    fn tip_snapshot_params(
        &self,
    ) -> Result<(ActiveProtocolParameters, ErgoValidationSettings), StateError> {
        Ok((
            CommittedSnapshot::active_params(self)?,
            CommittedSnapshot::validation_settings(self)?,
        ))
    }
    fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        CommittedSnapshot::candidate_dry_run(self, checked)
    }
    fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError> {
        CommittedSnapshot::mode2_trust_first_epoch_armed(self)
    }
}

/// A [`CandidateStateView`] over a committed snapshot that routes the AVL
/// dry-run through a per-tip pristine base cache. Every read except the
/// dry-run delegates straight to `snap`'s `CommittedSnapshot` impl (so the
/// candidate is sourced from the one held transaction exactly as the uncached
/// path); only [`candidate_dry_run`](CandidateStateView::candidate_dry_run)
/// consults `base`, calling [`CommittedSnapshot::candidate_dry_run_cached`] —
/// a cache hit reuses the memoized pristine tree (shallow COW clone), a
/// miss/tip-change full-rehydrates and re-memoizes.
///
/// After a build, [`Self::last_disposition`] returns the path the dry-run
/// took: [`BaseDisposition::Hit`], [`BaseDisposition::Advanced`],
/// [`BaseDisposition::Rehydrated`], or
/// [`BaseDisposition::RehydratedAfterFailedAdvance`]. The disposition is `None`
/// if no build has completed through this view yet (i.e. `candidate_dry_run`
/// has not been called).
///
/// The cached dry-run needs `&mut Option<DryRunBase>`, but the trait method is
/// `&self`. The borrow is reconciled with a [`RefCell`] around the borrowed
/// slot. This is sound because the build is strictly single-threaded and
/// serial: the base graph is `!Send` and lives on the engine's one dedicated
/// build worker thread, which runs at most one build at a time and calls
/// `candidate_dry_run` exactly once per build. There is no other live borrow
/// of the slot during a build, so the `RefCell` never double-borrows; it is
/// purely the type-level bridge from the trait's `&self` to the cache's
/// `&mut`, not a guard against real aliasing.
pub struct CachedSnapshotView<'a> {
    snap: &'a CommittedSnapshot,
    base: RefCell<&'a mut Option<DryRunBase>>,
    /// The disposition reported by the most recent `candidate_dry_run` call.
    /// `Cell` (not `RefCell`) because we write a `Copy` value and never hold a
    /// borrow — there is no aliasing hazard.
    disposition: Cell<Option<BaseDisposition>>,
}

impl<'a> CachedSnapshotView<'a> {
    /// Wrap `snap` so its dry-run routes through the per-tip `base` cache.
    pub fn new(snap: &'a CommittedSnapshot, base: &'a mut Option<DryRunBase>) -> Self {
        Self {
            snap,
            base: RefCell::new(base),
            disposition: Cell::new(None),
        }
    }

    /// The path taken by the most recent [`CandidateStateView::candidate_dry_run`]
    /// call through this view. `None` if no build has run yet.
    pub fn last_disposition(&self) -> Option<BaseDisposition> {
        self.disposition.get()
    }
}

impl UtxoView for CachedSnapshotView<'_> {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.snap.get_box(box_id)
    }
}

impl CandidateStateView for CachedSnapshotView<'_> {
    fn emission_identity(&self, tip: &[u8; 32]) -> Result<Option<Option<Digest32>>, StateError> {
        CommittedSnapshot::emission_identity(self.snap, tip)
    }
    fn best_full_block_id(&self) -> [u8; 32] {
        CommittedSnapshot::best_full_block_id(self.snap)
    }
    fn best_full_block_height(&self) -> u32 {
        CommittedSnapshot::best_full_block_height(self.snap)
    }
    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::get_header_bytes(self.snap, id)
    }
    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        CommittedSnapshot::header_id_at_height(self.snap, height)
    }
    fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::block_section(self.snap, modifier_id)
    }
    fn last_applied_chain_window_10(&self) -> Result<[Header; 10], StateError> {
        CommittedSnapshot::last_headers_window(self.snap)
    }
    fn tip_snapshot_params(
        &self,
    ) -> Result<(ActiveProtocolParameters, ErgoValidationSettings), StateError> {
        Ok((
            CommittedSnapshot::active_params(self.snap)?,
            CommittedSnapshot::validation_settings(self.snap)?,
        ))
    }
    fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        // Single serial build thread (see the type doc): this is the only
        // borrow of the slot for the duration of the build, so the `RefCell`
        // borrow can never conflict.
        let mut base = self.base.borrow_mut();
        // `base: RefMut<&mut Option<DryRunBase>>`; `&mut base` auto-derefs
        // through `DerefMut` to the `&mut Option<DryRunBase>` the cache wants.
        let mut disp: Option<BaseDisposition> = None;
        let result = self
            .snap
            .candidate_dry_run_cached(&mut base, checked, &mut disp);
        // Record disposition even on error (the path taken is still informative).
        self.disposition.set(disp);
        result
    }
    fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError> {
        CommittedSnapshot::mode2_trust_first_epoch_armed(self.snap)
    }
}

/// One successful candidate proof, reused only for the same parent state and
/// identical ordered transactions. This cache stores owned bytes, never a
/// mutable AVL graph or a transaction's context-dependent validation result.
/// A different request replaces the entry rather than growing a dictionary.
/// Storage is bounded to one candidate's transaction bytes and one proof; the
/// production builder enforces the voted block size and cost limits first.
#[derive(Default)]
pub struct CandidateProofCache {
    entry: Option<CachedCandidateProof>,
}

#[derive(PartialEq, Eq)]
struct CandidateProofKey {
    parent_id: [u8; 32],
    parent_root: ADDigest,
    /// Exact equality avoids a hash-only cache key. The checked id is included
    /// because it supplies output-box identity to the state-change builder.
    transactions: Vec<([u8; 32], Vec<u8>)>,
}

struct CachedCandidateProof {
    key: CandidateProofKey,
    state_root: ADDigest,
    proof: Vec<u8>,
}

/// Wrap a consistent state view with bounded reuse of its last successful
/// proof. All reads and transaction validation still use `view`; only the
/// final AVL dry-run can reuse its result. The caller must supply the parent
/// root from that same held committed snapshot.
///
/// The conservative key contains the parent id, its state root, and every
/// checked transaction's id and complete canonical serialization in block
/// order. Equality therefore preserves the canonical operation stream,
/// including data-input lookup order and duplicates, create/spend netting,
/// and serialized inserted boxes. Changes to witnesses also miss, although
/// witnesses alone do not change state. No cross-tip or equal-height fork
/// reuse is possible.
///
/// A hit requires freshly checked transactions. Scripts can read the new
/// pre-header timestamp, so earlier mempool or candidate validation is never
/// cached here. Misses execute the underlying proof generation and self-check;
/// only a successful result for the expected parent is stored. Wrapping a
/// [`CachedSnapshotView`] leaves its pristine-base poison guard unchanged.
pub struct ProofCachingView<'a, V: CandidateStateView> {
    view: &'a V,
    parent_root: ADDigest,
    cache: RefCell<&'a mut CandidateProofCache>,
    hit: Cell<Option<bool>>,
}

impl<'a, V: CandidateStateView> ProofCachingView<'a, V> {
    pub fn new(view: &'a V, parent_root: ADDigest, cache: &'a mut CandidateProofCache) -> Self {
        Self {
            view,
            parent_root,
            cache: RefCell::new(cache),
            hit: Cell::new(None),
        }
    }

    /// Whether the most recent dry-run reused its proof. `None` means the
    /// candidate has not reached the dry-run through this view.
    pub fn cache_hit(&self) -> Option<bool> {
        self.hit.get()
    }
}

impl<V: CandidateStateView> UtxoView for ProofCachingView<'_, V> {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.view.get_box(box_id)
    }
}

impl<V: CandidateStateView> CandidateStateView for ProofCachingView<'_, V> {
    fn emission_identity(&self, tip: &[u8; 32]) -> Result<Option<Option<Digest32>>, StateError> {
        self.view.emission_identity(tip)
    }

    fn best_full_block_id(&self) -> [u8; 32] {
        self.view.best_full_block_id()
    }

    fn best_full_block_height(&self) -> u32 {
        self.view.best_full_block_height()
    }

    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        self.view.get_header_bytes(id)
    }

    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        self.view.header_id_at_height(height)
    }

    fn block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        self.view.block_section(modifier_id)
    }

    fn last_applied_chain_window_10(&self) -> Result<[Header; 10], StateError> {
        self.view.last_applied_chain_window_10()
    }

    fn tip_snapshot_params(
        &self,
    ) -> Result<(ActiveProtocolParameters, ErgoValidationSettings), StateError> {
        self.view.tip_snapshot_params()
    }

    fn candidate_dry_run(
        &self,
        checked: &[CheckedTransaction],
    ) -> Result<(ADDigest, Vec<u8>, [u8; 32]), StateError> {
        self.hit.set(Some(false));
        let parent_id = self.view.best_full_block_id();
        let transactions = checked
            .iter()
            .map(|tx| {
                let mut writer = VlqWriter::new();
                write_transaction(&mut writer, tx.transaction())
                    .map_err(|e| StateError::Serialization(format!("candidate proof key: {e}")))?;
                Ok((*tx.tx_id(), writer.result()))
            })
            .collect::<Result<Vec<_>, StateError>>()?;
        let key = CandidateProofKey {
            parent_id,
            parent_root: self.parent_root,
            transactions,
        };

        {
            let mut cache = self.cache.borrow_mut();
            if let Some(entry) = &cache.entry {
                if entry.key == key {
                    self.hit.set(Some(true));
                    return Ok((entry.state_root, entry.proof.clone(), parent_id));
                }
            }
            // Drop the old proof before a miss. A failed or unwinding dry-run
            // leaves no cached result and follows the underlying base's poison
            // contract without consulting any mutable graph on the hit path.
            cache.entry = None;
        }

        let result = self.view.candidate_dry_run(checked)?;
        if result.2 == parent_id {
            self.cache.borrow_mut().entry = Some(CachedCandidateProof {
                key,
                state_root: result.0,
                proof: result.1.clone(),
            });
        }
        Ok(result)
    }

    fn mode2_trust_first_epoch_armed(&self) -> Result<bool, StateError> {
        self.view.mode2_trust_first_epoch_armed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use ergo_primitives::{digest::blake2b256, reader::VlqReader};
    use ergo_ser::{
        autolykos::AutolykosSolution,
        ergo_box::read_ergo_box,
        header::{read_header, serialize_header},
        input::DataInput,
        sigma_type::SigmaType,
        sigma_value::SigmaValue,
        transaction::read_transaction,
    };
    use ergo_validation::{
        validate_transaction_parsed, CostAccumulator, JitCost, ProtocolParams, TransactionContext,
        TxValidationCtx, TxValidationRules,
    };
    use serde::Deserialize;

    // ----- helpers -----

    #[derive(Deserialize)]
    struct OracleBlock {
        header_hex: String,
        transactions_hex: Vec<String>,
        ad_proofs_hex: String,
    }

    #[derive(Deserialize)]
    struct OracleFixture {
        initial_box_order_hex: Vec<String>,
        genesis_state_root: String,
        parent_blocks: Vec<OracleBlock>,
        parent_state_root: String,
        parameters: BTreeMap<String, i32>,
        block: OracleBlock,
    }

    fn oracle_fixture() -> OracleFixture {
        let bytes = include_bytes!("../../test-vectors/ergo-sigma/cost-ledger/blocks/p2pk.json.gz");
        serde_json::from_reader(flate2::read::GzDecoder::new(bytes.as_slice())).unwrap()
    }

    fn oracle_header(block: &OracleBlock) -> Header {
        read_header(&mut VlqReader::new(
            &hex::decode(&block.header_hex).unwrap(),
        ))
        .unwrap()
    }

    fn oracle_store(fixture: &OracleFixture) -> (tempfile::TempDir, StateStore) {
        let directory = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&directory.path().join("state.redb")).unwrap();
        let boxes: Vec<_> = fixture
            .initial_box_order_hex
            .iter()
            .map(|encoded| {
                let bytes = hex::decode(encoded).unwrap();
                let value = read_ergo_box(&mut VlqReader::new(&bytes)).unwrap();
                (*value.box_id().unwrap().as_bytes(), bytes)
            })
            .collect();
        store.initialize_genesis(&boxes).unwrap();
        assert_eq!(
            hex::encode(store.root_digest().as_bytes()),
            fixture.genesis_state_root,
            "initial insertion order must reconstruct the Scala genesis state"
        );
        for block in &fixture.parent_blocks {
            let header = oracle_header(block);
            let (bytes, id) = serialize_header(&header).unwrap();
            assert_eq!(hex::encode(&bytes), block.header_hex);
            store.store_header(id.as_bytes(), &bytes).unwrap();
            let transactions: Vec<_> = block
                .transactions_hex
                .iter()
                .map(|encoded| {
                    read_transaction(&mut VlqReader::new(&hex::decode(encoded).unwrap())).unwrap()
                })
                .collect();
            // These parent transitions are externally fixed Scala state
            // fixtures; the test-only apply checks each recorded state root.
            store
                .apply_block_unchecked_for_test(
                    header.height,
                    id.as_bytes(),
                    &header.state_root,
                    &transactions,
                )
                .unwrap();
        }
        store.flush_persist_pipeline().unwrap();
        assert_eq!(
            hex::encode(store.root_digest().as_bytes()),
            fixture.parent_state_root
        );
        (directory, store)
    }

    fn oracle_checked(
        fixture: &OracleFixture,
        view: &impl CandidateStateView,
        timestamp: u64,
        skip_scripts: bool,
        mutate: impl Fn(&mut ergo_ser::transaction::Transaction),
    ) -> Vec<CheckedTransaction> {
        let header = oracle_header(&fixture.block);
        let miner_pubkey = match &header.solution {
            AutolykosSolution::V2 { pk, .. } => *pk.as_bytes(),
            AutolykosSolution::V1 { .. } => panic!("oracle uses Autolykos v2"),
        };
        let params = ProtocolParams {
            storage_fee_factor: fixture.parameters["1"],
            min_value_per_byte: fixture.parameters["2"] as u64,
            max_block_size: fixture.parameters["3"] as u32,
            max_block_cost: fixture.parameters["4"] as u64,
            token_access_cost: fixture.parameters["5"] as u64,
            input_cost: fixture.parameters["6"] as u64,
            data_input_cost: fixture.parameters["7"] as u64,
            output_cost: fixture.parameters["8"] as u64,
            ..ProtocolParams::mainnet_default()
        };
        let ctx = TransactionContext {
            height: header.height,
            miner_pubkey,
            pre_header_timestamp: timestamp,
            activated_script_version: header.version - 1,
            pre_header_version: header.version,
            pre_header_parent_id: *header.parent_id.as_bytes(),
            pre_header_n_bits: u64::from(header.n_bits),
            pre_header_votes: header.votes,
        };
        let last_headers = view.last_applied_chain_window_10().unwrap();
        fixture
            .block
            .transactions_hex
            .iter()
            .map(|encoded| {
                let mut tx =
                    read_transaction(&mut VlqReader::new(&hex::decode(encoded).unwrap())).unwrap();
                mutate(&mut tx);
                let mut writer = VlqWriter::new();
                write_transaction(&mut writer, &tx).unwrap();
                let bytes = writer.result();
                let inputs = tx
                    .inputs
                    .iter()
                    .map(|input| view.get_box(&input.box_id).unwrap())
                    .collect();
                let data_inputs = tx
                    .data_inputs
                    .iter()
                    .map(|input| view.get_box(&input.box_id).unwrap())
                    .collect();
                let mut cost =
                    CostAccumulator::new(JitCost::from_block_cost(params.max_block_cost).unwrap());
                let mut validation = TxValidationCtx {
                    ctx: &ctx,
                    params: &params,
                    cost: &mut cost,
                    last_headers: &last_headers,
                    rules: TxValidationRules::default(),
                };
                validate_transaction_parsed(
                    tx,
                    &bytes,
                    inputs,
                    data_inputs,
                    skip_scripts,
                    &mut validation,
                )
                .unwrap()
            })
            .collect()
    }

    // ----- error paths -----

    #[test]
    fn proof_cache_failed_miss_drops_prior_result_and_preserves_base_poison_contract() {
        let fixture = oracle_fixture();
        let (_directory, store) = oracle_store(&fixture);
        let snapshot = store.committed_snapshot().unwrap().unwrap();
        let header = oracle_header(&fixture.block);
        let checked = oracle_checked(&fixture, &snapshot, header.timestamp, false, |_| {});
        let mut base = None;
        let mut cache = CandidateProofCache::default();
        {
            let underlying = CachedSnapshotView::new(&snapshot, &mut base);
            let view = ProofCachingView::new(&underlying, snapshot.state_root(), &mut cache);
            view.candidate_dry_run(&checked).unwrap();
        }
        assert!(cache.entry.is_some());
        assert!(base.is_some());

        // A validated transaction cannot normally refer to a missing committed
        // input. Drive that failure using a second real, held snapshot after
        // applying the fixture's target: its input is now spent. Supplying the
        // previous parent's CheckedTransaction only exercises the proof seam;
        // production candidate validation would already reject it.
        drop(snapshot);
        let mut store = store;
        let (bytes, id) = serialize_header(&header).unwrap();
        store.store_header(id.as_bytes(), &bytes).unwrap();
        let raw: Vec<_> = checked.iter().map(|tx| tx.transaction().clone()).collect();
        store
            .apply_block_unchecked_for_test(header.height, id.as_bytes(), &header.state_root, &raw)
            .unwrap();
        store.flush_persist_pipeline().unwrap();
        let next = store.committed_snapshot().unwrap().unwrap();
        {
            let underlying = CachedSnapshotView::new(&next, &mut base);
            let view = ProofCachingView::new(&underlying, next.state_root(), &mut cache);
            assert!(view.candidate_dry_run(&checked).is_err());
            assert_eq!(view.cache_hit(), Some(false));
        }
        assert!(cache.entry.is_none());
        assert!(base.is_none(), "failed AVL operation must poison the base");
    }

    // ----- oracle parity -----

    /// Producer and complete insertion/replay recipe:
    /// scripts/jvm_block_oracle/BlockOracle.scala and the fixture README.
    /// Expected proof/root are Scala-produced bytes, never the Rust miss.
    #[test]
    fn proof_cache_revalidated_same_parent_matches_scala_proof_and_state_root() {
        let fixture = oracle_fixture();
        let (_directory, store) = oracle_store(&fixture);
        let snapshot = store.committed_snapshot().unwrap().unwrap();
        let header = oracle_header(&fixture.block);
        let expected_proof = hex::decode(&fixture.block.ad_proofs_hex).unwrap();
        let mut cache = CandidateProofCache::default();
        for (pass, timestamp) in [header.timestamp, header.timestamp + 1]
            .into_iter()
            .enumerate()
        {
            // Re-run full transaction/script validation for both timestamps.
            // Only the resulting state proof is eligible for reuse.
            let checked = oracle_checked(&fixture, &snapshot, timestamp, false, |_| {});
            let view = ProofCachingView::new(&snapshot, snapshot.state_root(), &mut cache);
            let result = view.candidate_dry_run(&checked).unwrap();
            assert_eq!(view.cache_hit(), Some(pass != 0));
            assert_eq!(result.0, header.state_root);
            assert_eq!(result.1, expected_proof);
            assert_eq!(result.2, *header.parent_id.as_bytes());
            assert_eq!(blake2b256(&result.1), header.ad_proofs_root);
        }
    }

    #[test]
    fn proof_cache_changed_context_extension_and_lookup_order_miss() {
        let fixture = oracle_fixture();
        let (_directory, store) = oracle_store(&fixture);
        let snapshot = store.committed_snapshot().unwrap().unwrap();
        let header = oracle_header(&fixture.block);
        let mut cache = CandidateProofCache::default();
        let original = oracle_checked(&fixture, &snapshot, header.timestamp, false, |_| {});
        let data_a = original[0].transaction().inputs[0].box_id;
        let bootstrap_tx = read_transaction(&mut VlqReader::new(
            &hex::decode(&fixture.parent_blocks.last().unwrap().transactions_hex[0]).unwrap(),
        ))
        .unwrap();
        let bootstrap_id = ergo_ser::transaction::transaction_id(&bootstrap_tx).unwrap();
        let bootstrap_box = ErgoBox {
            candidate: bootstrap_tx.output_candidates[0].clone(),
            transaction_id: bootstrap_id,
            index: 0,
        };
        let data_b = bootstrap_box.box_id().unwrap();

        for (extension, lookups) in [
            (false, vec![]),
            (true, vec![]),
            (true, vec![data_a, data_b]),
            (true, vec![data_b, data_a]),
            (true, vec![data_b, data_a, data_a]),
            (false, vec![]),
        ] {
            // Mutating signed bytes invalidates this fixture's signature;
            // scripts are skipped solely to create CheckedTransaction inputs
            // for cache-key coverage. The full-validation parity test above
            // supplies the external consensus evidence.
            let checked = oracle_checked(&fixture, &snapshot, header.timestamp, true, |tx| {
                if extension {
                    let mut values = tx.inputs[0].spending_proof.extension().clone();
                    values
                        .values
                        .insert(7, (SigmaType::SShort, SigmaValue::Short(1)));
                    tx.inputs[0].spending_proof = ergo_ser::input::SpendingProof::new(
                        tx.inputs[0].spending_proof.proof.clone(),
                        values,
                    )
                    .unwrap();
                }
                tx.data_inputs = lookups
                    .iter()
                    .map(|box_id| DataInput { box_id: *box_id })
                    .collect();
            });
            let expected = snapshot.candidate_dry_run(&checked).unwrap();
            let view = ProofCachingView::new(&snapshot, snapshot.state_root(), &mut cache);
            assert_eq!(view.candidate_dry_run(&checked).unwrap(), expected);
            assert_eq!(view.cache_hit(), Some(false));
        }
    }
}
