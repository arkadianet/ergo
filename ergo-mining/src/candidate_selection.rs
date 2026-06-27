//! In-block UTXO overlay + greedy mempool selection for candidate
//! assembly.
//!
//! Mirrors the consensus behavior of `ergo-validation`'s block validator
//! so a candidate this selects is one the validator (the parity anchor
//! that judges the submitted block) will accept:
//!
//! - The overlay replicates `BlockUtxoOverlay`'s two distinct resolution
//!   rules — regular inputs filter intra-block spends and surface
//!   intra-block creates; data inputs surface creates but DO NOT filter
//!   spends (mainnet block 422179 parity). It is fallible where the
//!   validator's is not: selection sees unvalidated mempool txs, so a box
//!   whose id can't be derived is skipped, never `expect()`-panicked.
//! - Selection is a sequential greedy pass in the snapshot's
//!   relay-priority order, mirroring Scala `CandidateGenerator.collectTxs`:
//!   skip any tx that double-spends an already-consumed box (this is how a
//!   pinned storage-rent self-claim excludes conflicting fee-bearing bot
//!   claims — seed the overlay with the rent tx first), skip any tx that
//!   fails revalidation against the candidate's frozen context, and stop
//!   when the running block cost/size budget would be exceeded.
//! - Block cost is summed exactly as the validator does: each tx is
//!   validated with its OWN fresh `CostAccumulator` (because `add` commits
//!   before checking the limit, a shared accumulator would be polluted by
//!   a rejected tx), and the per-tx `total_block_cost()` is folded into a
//!   running total compared against the budget.

use std::collections::{HashMap, HashSet};

use ergo_mempool::MempoolReadSnapshot;
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_ser::transaction::{read_transaction, transaction_id, Transaction};
use ergo_validation::{
    validate_transaction_parsed, CheckedTransaction, CostAccumulator, JitCost, ProtocolParams,
    ReemissionRuleInputs, TransactionContext, TxValidationCtx, TxValidationRules, UtxoView,
};

use crate::error::MiningError;

/// Intra-block UTXO overlay over a base `UtxoView` (the committed state
/// tip). Tracks boxes created and spent by txs already placed in the
/// candidate so later txs can spend earlier outputs and conflicts are
/// excluded.
pub struct CandidateOverlay<'a> {
    base: &'a dyn UtxoView,
    in_block_outputs: HashMap<Digest32, ErgoBox>,
    spent_in_block: HashSet<Digest32>,
}

impl<'a> CandidateOverlay<'a> {
    pub fn new(base: &'a dyn UtxoView) -> Self {
        Self {
            base,
            in_block_outputs: HashMap::new(),
            spent_in_block: HashSet::new(),
        }
    }

    /// Record a tx's effects: its inputs become spent, its outputs become
    /// available to later txs. Returns an error only if the tx id can't be
    /// derived (a malformed already-structurally-validated tx); the caller
    /// applies only txs that have passed validation, so this never fails in
    /// practice, but it is surfaced rather than panicked.
    pub fn apply_tx(&mut self, tx: &Transaction) -> Result<(), MiningError> {
        for input in &tx.inputs {
            self.spent_in_block.insert(input.box_id);
        }
        let tx_id = transaction_id(tx).map_err(|e| MiningError::IdComputation {
            op: "overlay_tx_id",
            reason: format!("{e:?}"),
        })?;
        for (idx, output) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: output.clone(),
                transaction_id: tx_id,
                index: idx as u16,
            };
            if let Ok(box_id) = ergo_box.box_id() {
                self.in_block_outputs.insert(box_id, ergo_box);
            }
        }
        Ok(())
    }

    /// True if `box_id` has been spent by a tx already in the candidate.
    pub fn is_spent(&self, box_id: &Digest32) -> bool {
        self.spent_in_block.contains(box_id)
    }

    /// Resolve a regular input: `None` if spent in-block, else an
    /// intra-block create, else the base UTXO set.
    fn resolve_input(&self, box_id: &Digest32) -> Option<ErgoBox> {
        if self.spent_in_block.contains(box_id) {
            return None;
        }
        self.in_block_outputs
            .get(box_id)
            .cloned()
            .or_else(|| self.base.get_box(box_id))
    }

    /// Resolve a data input: an intra-block create, else the base UTXO
    /// set. Does NOT filter intra-block spends (mainnet block 422179
    /// parity).
    fn resolve_data_input(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.in_block_outputs
            .get(box_id)
            .cloned()
            .or_else(|| self.base.get_box(box_id))
    }

    fn resolve_inputs(&self, tx: &Transaction) -> Option<Vec<ErgoBox>> {
        tx.inputs
            .iter()
            .map(|i| self.resolve_input(&i.box_id))
            .collect()
    }

    fn resolve_data_inputs(&self, tx: &Transaction) -> Option<Vec<ErgoBox>> {
        tx.data_inputs
            .iter()
            .map(|d| self.resolve_data_input(&d.box_id))
            .collect()
    }

    /// Resolve a transaction's regular + data inputs against the overlay,
    /// for validating a tx assembled after selection (e.g. the fee tx,
    /// which spends fee-proposition outputs of already-included user txs).
    /// `None` if any input is unresolved.
    pub fn resolve_tx(&self, tx: &Transaction) -> Option<(Vec<ErgoBox>, Vec<ErgoBox>)> {
        Some((self.resolve_inputs(tx)?, self.resolve_data_inputs(tx)?))
    }
}

/// Outcome of mempool selection.
#[derive(Debug, Default)]
pub struct Selected {
    /// Validated user transactions in inclusion order, each paired with its
    /// block cost. The per-tx cost lets the caller recompute the block-cost
    /// total as it trims the tail to fit the fee tx + size cap.
    pub checked: Vec<(CheckedTransaction, u64)>,
    /// Sum of selected transactions' fees (nanoERG).
    pub total_fee: u64,
    /// Sum of selected transactions' block cost.
    pub total_cost: u64,
    /// Sum of selected transactions' serialized sizes (bytes).
    pub total_size: u64,
    /// Pooled txs whose CONSENSUS re-validation failed against the candidate's
    /// frozen tip+1 context (Component B's "suspect" feed). These are the only
    /// skip class that maps to a provable invalidity; the node re-validates each
    /// against the live tip and evicts the still-invalid ones
    /// (`Mempool::recheck_ids`). Resolve/conflict/budget skips are deliberately
    /// NOT collected — they are in-block ordering / fit losses, not tx
    /// invalidity, and would be re-validated as non-hard-invalid (kept) anyway.
    pub suspects: Vec<Digest32>,
}

/// Greedily select mempool transactions into the candidate.
///
/// `overlay` must already have the pinned txs (emission, and the
/// storage-rent self-claim if any) applied, so their consumed boxes are in
/// the spent set before selection — that is what excludes conflicting
/// fee-bearing claims. Selected txs are applied to `overlay` so a later
/// fee-collecting tx can resolve their fee outputs.
///
/// `cost_budget` / `size_budget` are the block budgets remaining after the
/// pinned txs (and a safety gap); selection stops at the first tx that
/// would exceed either. Transactions that conflict, fail to resolve, or
/// fail revalidation are skipped.
#[allow(clippy::too_many_arguments)]
pub fn select_user_txs(
    overlay: &mut CandidateOverlay,
    snapshot: &MempoolReadSnapshot,
    ctx: &TransactionContext,
    params: &ProtocolParams,
    last_headers: &[Header],
    cost_budget: u64,
    size_budget: u64,
    reemission_rules: Option<&ReemissionRuleInputs>,
) -> Result<Selected, MiningError> {
    let block_cap = JitCost::from_block_cost(params.max_block_cost).map_err(|e| {
        MiningError::IdComputation {
            op: "select_block_cap",
            reason: format!("{e:?}"),
        }
    })?;

    let mut sel = Selected::default();

    for entry in snapshot.iter() {
        // Size budget: stop once the next tx would overrun the block.
        if sel.total_size.saturating_add(u64::from(entry.size_bytes)) > size_budget {
            break;
        }

        // Conflict / double-spend: cheap precheck on the precomputed input
        // ids before parsing. Excludes fee-bearing bot claims on a box the
        // pinned rent tx already consumed, and intra-block double-spends.
        if entry.inputs.iter().any(|id| overlay.is_spent(id)) {
            continue;
        }

        let tx = match parse_tx(&entry.bytes) {
            Ok(t) => t,
            Err(_) => continue,
        };

        // Resolve inputs/data-inputs against the evolving overlay. A None
        // means an input is already spent in-block or not yet available
        // (e.g. a child whose parent was not included) — skip the tx.
        let Some(resolved_inputs) = overlay.resolve_inputs(&tx) else {
            continue;
        };
        let Some(resolved_data_inputs) = overlay.resolve_data_inputs(&tx) else {
            continue;
        };

        // Revalidate against the candidate's frozen context with a FRESH
        // accumulator (a shared one would be polluted by a rejected tx).
        let mut cost = CostAccumulator::new(block_cap);
        let checked = {
            let mut cx = TxValidationCtx {
                ctx,
                params,
                cost: &mut cost,
                last_headers,
                rules: TxValidationRules {
                    reemission: reemission_rules,
                },
            };
            match validate_transaction_parsed(
                tx.clone(),
                &entry.bytes,
                resolved_inputs,
                resolved_data_inputs,
                false,
                &mut cx,
            ) {
                Ok(c) => c,
                Err(_) => {
                    // Consensus re-validation failed against the candidate's
                    // tip+1 context: this tx is (likely) invalid at the new tip.
                    // Flag it as a suspect so the node re-validates it live and
                    // evicts it if still invalid — instead of it lingering until
                    // the next full recheck pass. (Only this skip class is
                    // collected; see `Selected::suspects`.)
                    sel.suspects.push(entry.tx_id);
                    continue;
                }
            }
        };

        // Cost budget: stop if this tx would push the block over.
        let tx_cost = cost.total_block_cost();
        if sel.total_cost.saturating_add(tx_cost) > cost_budget {
            break;
        }

        overlay.apply_tx(&tx)?;
        sel.total_cost = sel.total_cost.saturating_add(tx_cost);
        sel.total_size = sel.total_size.saturating_add(u64::from(entry.size_bytes));
        sel.total_fee = sel.total_fee.saturating_add(entry.fee);
        sel.checked.push((checked, tx_cost));
    }

    Ok(sel)
}

fn parse_tx(bytes: &[u8]) -> Result<Transaction, MiningError> {
    let mut r = VlqReader::new(bytes);
    let tx = read_transaction(&mut r).map_err(|e| MiningError::Decode {
        op: "mempool_tx_parse",
        reason: format!("{e:?}"),
    })?;
    if !r.is_empty() {
        return Err(MiningError::Decode {
            op: "mempool_tx_parse",
            reason: "trailing bytes after transaction".into(),
        });
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_mempool::pool::Entry;
    use ergo_mempool::types::TxSource;
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, DataInput, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_ser::transaction::write_transaction;

    // ----- helpers -----

    /// A `sigmaProp(true)` proposition — spendable with an empty proof.
    ///
    /// The root must be `SSigmaProp`: a non-SigmaProp root (e.g.
    /// `Const(SBoolean, true)`) fails Scala's
    /// `CheckDeserializedScriptIsSigmaProp` and is soft-fork-wrapped into
    /// `Expr::Unparsed` on re-parse (then unspendable), so it would not
    /// survive the serialize → `parse_tx` round-trip this selector performs.
    fn trivial_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(ergo_ser::sigma_value::SigmaBoolean::TrivialProp(true)),
            },
        }
    }

    fn box_at(value: u64, creation_height: u32, tx_seed: u8) -> ErgoBox {
        ErgoBox {
            candidate: ErgoBoxCandidate::new(
                value,
                trivial_tree(),
                creation_height,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([tx_seed; 32]),
            index: 0,
        }
    }

    /// A tx spending `input` (empty proof; trivial-true → valid) into a
    /// single trivial-true output of `out_value` at `height`.
    fn spend_tx(input: &ErgoBox, out_value: u64, height: u32) -> Transaction {
        Transaction {
            inputs: vec![Input {
                box_id: input.box_id().unwrap(),
                spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate::new(
                out_value,
                trivial_tree(),
                height,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap()],
        }
    }

    /// Like `spend_tx` but also references `data` as a read-only data input.
    fn spend_tx_with_data_input(
        spend: &ErgoBox,
        data: &ErgoBox,
        out_value: u64,
        height: u32,
    ) -> Transaction {
        Transaction {
            inputs: vec![Input {
                box_id: spend.box_id().unwrap(),
                spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![DataInput {
                box_id: data.box_id().unwrap(),
            }],
            output_candidates: vec![ErgoBoxCandidate::new(
                out_value,
                trivial_tree(),
                height,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap()],
        }
    }

    fn tx_bytes(tx: &Transaction) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_transaction(&mut w, tx).unwrap();
        w.result()
    }

    /// A mempool entry wrapping `tx` with the given fee/size for budgeting.
    fn entry(tx: &Transaction, fee: u64, size_bytes: u32, seed: u8) -> Entry {
        let bytes = tx_bytes(tx);
        Entry {
            tx_id: Digest32::from_bytes([seed; 32]),
            bytes: std::sync::Arc::from(bytes.into_boxed_slice()),
            inputs: tx.inputs.iter().map(|i| i.box_id).collect(),
            outputs: Vec::new(),
            parents_in_pool: Vec::new(),
            fee,
            weight: fee,
            size_bytes,
            cost: 1000,
            created_at: std::time::Instant::now(),
            last_checked_at: std::time::Instant::now(),
            source: TxSource::Api,
            output_boxes: Vec::new(),
        }
    }

    struct MapUtxo {
        boxes: HashMap<Digest32, ErgoBox>,
    }
    impl MapUtxo {
        fn new(boxes: &[ErgoBox]) -> Self {
            Self {
                boxes: boxes
                    .iter()
                    .map(|b| (b.box_id().unwrap(), b.clone()))
                    .collect(),
            }
        }
    }
    impl UtxoView for MapUtxo {
        fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
            self.boxes.get(box_id).cloned()
        }
    }

    const HEIGHT: u32 = 100;

    fn ctx() -> TransactionContext {
        TransactionContext {
            height: HEIGHT,
            miner_pubkey: [0u8; 33],
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        }
    }

    // ----- happy path -----

    #[test]
    fn selects_a_valid_nonconflicting_tx() {
        let in_box = box_at(1_000_000_000, HEIGHT, 0x01);
        let utxo = MapUtxo::new(std::slice::from_ref(&in_box));
        let tx = spend_tx(&in_box, 1_000_000_000, HEIGHT);
        let snap = MempoolReadSnapshot::from_entries(vec![entry(&tx, 0, 100, 0xA0)]);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert_eq!(sel.checked.len(), 1, "a valid mempool tx must be selected");
        assert!(sel.suspects.is_empty(), "a selected tx is not a suspect");
    }

    // ----- suspect feed (Component B) -----

    #[test]
    fn revalidation_failure_is_collected_as_suspect() {
        // A tx that parses and resolves but FAILS consensus re-validation
        // (output value exceeds input — ERG not conserved) is skipped from the
        // candidate AND recorded in `suspects`, so the node can re-validate it
        // against the live tip and evict it if still invalid. This is the only
        // skip class that maps to a provable invalidity.
        let in_box = box_at(1_000_000_000, HEIGHT, 0x01);
        let utxo = MapUtxo::new(std::slice::from_ref(&in_box));
        let tx = spend_tx(&in_box, 2_000_000_000, HEIGHT); // out > in: not conserved
        let snap = MempoolReadSnapshot::from_entries(vec![entry(&tx, 0, 100, 0xA0)]);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert!(
            sel.checked.is_empty(),
            "a non-conserving tx must not be selected",
        );
        assert_eq!(
            sel.suspects,
            vec![Digest32::from_bytes([0xA0; 32])],
            "a consensus-revalidation failure is recorded as a suspect",
        );
    }

    // ----- conflict exclusion (the rent-claim core) -----

    #[test]
    fn tx_conflicting_with_a_pinned_input_is_excluded() {
        // The overlay is pre-seeded by applying a "pinned" tx (stand-in for
        // the storage-rent self-claim) that consumes `shared`. A mempool tx
        // spending the same box must be excluded.
        let shared = box_at(1_000_000_000, HEIGHT, 0x01);
        let utxo = MapUtxo::new(std::slice::from_ref(&shared));

        let pinned = spend_tx(&shared, 1_000_000_000, HEIGHT);
        let bot_claim = spend_tx(&shared, 1_000_000_000, HEIGHT); // same input
        let snap = MempoolReadSnapshot::from_entries(vec![entry(&bot_claim, 5000, 100, 0xB0)]);

        let mut overlay = CandidateOverlay::new(&utxo);
        overlay.apply_tx(&pinned).unwrap(); // seed spent set

        let params = ProtocolParams::mainnet_default();
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert!(
            sel.checked.is_empty(),
            "a tx conflicting with a pinned (rent) input must be excluded",
        );
        assert!(
            sel.suspects.is_empty(),
            "a conflict/double-spend skip is an in-block race loss, not tip-invalidity — not a suspect",
        );
    }

    #[test]
    fn second_double_spender_in_mempool_is_excluded() {
        let shared = box_at(1_000_000_000, HEIGHT, 0x01);
        let utxo = MapUtxo::new(std::slice::from_ref(&shared));
        let tx_a = spend_tx(&shared, 1_000_000_000, HEIGHT);
        let tx_b = spend_tx(&shared, 999_000_000, HEIGHT); // same input, distinct bytes
        let snap = MempoolReadSnapshot::from_entries(vec![
            entry(&tx_a, 10, 100, 0xA0),
            entry(&tx_b, 10, 100, 0xB0),
        ]);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert_eq!(
            sel.checked.len(),
            1,
            "only one spender of a box may be included"
        );
    }

    // ----- chained txs -----

    #[test]
    fn parent_before_child_includes_both() {
        // tx_parent spends a state box; tx_child spends tx_parent's output.
        let in_box = box_at(1_000_000_000, HEIGHT, 0x01);
        let utxo = MapUtxo::new(std::slice::from_ref(&in_box));
        let tx_parent = spend_tx(&in_box, 1_000_000_000, HEIGHT);

        let parent_id = transaction_id(&tx_parent).unwrap();
        let parent_out = ErgoBox {
            candidate: tx_parent.output_candidates[0].clone(),
            transaction_id: parent_id,
            index: 0,
        };
        let tx_child = spend_tx(&parent_out, 1_000_000_000, HEIGHT);

        let snap = MempoolReadSnapshot::from_entries(vec![
            entry(&tx_parent, 10, 100, 0xA0),
            entry(&tx_child, 10, 100, 0xB0),
        ]);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert_eq!(sel.checked.len(), 2, "parent then child: both included");
    }

    #[test]
    fn child_before_parent_skips_child() {
        // Same chain, but the child appears first. Its input (the parent's
        // output) is not yet in the overlay, so it is skipped (Scala
        // collectTxs parity — no reordering).
        let in_box = box_at(1_000_000_000, HEIGHT, 0x01);
        let utxo = MapUtxo::new(std::slice::from_ref(&in_box));
        let tx_parent = spend_tx(&in_box, 1_000_000_000, HEIGHT);
        let parent_id = transaction_id(&tx_parent).unwrap();
        let parent_out = ErgoBox {
            candidate: tx_parent.output_candidates[0].clone(),
            transaction_id: parent_id,
            index: 0,
        };
        let tx_child = spend_tx(&parent_out, 1_000_000_000, HEIGHT);

        let snap = MempoolReadSnapshot::from_entries(vec![
            entry(&tx_child, 10, 100, 0xB0),
            entry(&tx_parent, 10, 100, 0xA0),
        ]);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert_eq!(
            sel.checked.len(),
            1,
            "child-before-parent: only the parent is included this block",
        );
        assert!(
            sel.suspects.is_empty(),
            "an input-resolve skip is in-block ordering, not tip-invalidity — not a suspect",
        );
    }

    #[test]
    fn family_boosted_parent_selected_before_high_fee_child() {
        // CPFP: a low-fee parent whose family weight was boosted by its
        // high-fee child sorts AHEAD of that child, so the greedy pass takes
        // the parent first and includes the whole family. Without the boost
        // the high-fee child would sort first and be skipped (see
        // `child_before_parent_skips_child`). The snapshot reflects the
        // post-boost pool order: parent weight (own + child) > child weight.
        let in_box = box_at(1_000_000_000, HEIGHT, 0x01);
        let utxo = MapUtxo::new(std::slice::from_ref(&in_box));
        let tx_parent = spend_tx(&in_box, 1_000_000_000, HEIGHT);
        let parent_id = transaction_id(&tx_parent).unwrap();
        let parent_out = ErgoBox {
            candidate: tx_parent.output_candidates[0].clone(),
            transaction_id: parent_id,
            index: 0,
        };
        let tx_child = spend_tx(&parent_out, 1_000_000_000, HEIGHT);

        // Child's own weight is high (990); the parent, boosted by the child,
        // is 10 + 990 = 1000 and therefore ordered first.
        let snap = MempoolReadSnapshot::from_entries(vec![
            entry(&tx_parent, 1000, 100, 0xA0),
            entry(&tx_child, 990, 100, 0xB0),
        ]);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert_eq!(
            sel.checked.len(),
            2,
            "boosted parent first → whole CPFP family included",
        );
    }

    // ----- budgets -----

    #[test]
    fn size_budget_stops_selection() {
        let boxes: Vec<ErgoBox> = (0..3)
            .map(|i| box_at(1_000_000_000, HEIGHT, i + 1))
            .collect();
        let utxo = MapUtxo::new(&boxes);
        let entries: Vec<Entry> = boxes
            .iter()
            .enumerate()
            .map(|(i, b)| entry(&spend_tx(b, 1_000_000_000, HEIGHT), 10, 100, 0xA0 + i as u8))
            .collect();
        let snap = MempoolReadSnapshot::from_entries(entries);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        // 250-byte budget at 100 bytes each → 2 fit, the 3rd overruns.
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            250,
            None,
        )
        .unwrap();

        assert_eq!(sel.checked.len(), 2, "size budget must stop at 2 txs");
        assert_eq!(sel.total_size, 200);
    }

    #[test]
    fn zero_cost_budget_selects_nothing() {
        let in_box = box_at(1_000_000_000, HEIGHT, 0x01);
        let utxo = MapUtxo::new(std::slice::from_ref(&in_box));
        let tx = spend_tx(&in_box, 1_000_000_000, HEIGHT);
        let snap = MempoolReadSnapshot::from_entries(vec![entry(&tx, 0, 100, 0xA0)]);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        let sel =
            select_user_txs(&mut overlay, &snap, &ctx(), &params, &[], 0, u64::MAX, None).unwrap();

        assert!(sel.checked.is_empty(), "a zero cost budget admits nothing");
    }

    // ----- invalid tx skip -----

    #[test]
    fn tx_with_unresolved_input_is_skipped() {
        // The mempool tx spends a box not in the UTXO set (and not created
        // in-block) → unresolved → skipped, not an error.
        let absent = box_at(1_000_000_000, HEIGHT, 0xEE);
        let utxo = MapUtxo::new(&[]); // empty UTXO
        let tx = spend_tx(&absent, 1_000_000_000, HEIGHT);
        let snap = MempoolReadSnapshot::from_entries(vec![entry(&tx, 10, 100, 0xA0)]);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert!(
            sel.checked.is_empty(),
            "unresolved-input tx must be skipped"
        );
    }

    // ----- data-input parity (validator: surface creates, ignore spends) -----

    #[test]
    fn data_input_on_an_in_block_spent_box_still_resolves() {
        // Validator parity (mainnet block 422179): a DATA input resolves
        // against pre-block UTXO + in-block creates but is NOT filtered by
        // in-block spends. tx1 spends box A; tx2 spends box D and DATA-reads
        // A. Even though A is spent in-block, tx2's data input resolves, so
        // both are selected. (A regular input on A would instead be skipped
        // — see second_double_spender_in_mempool_is_excluded.)
        let box_a = box_at(1_000_000_000, HEIGHT, 0x01);
        let box_d = box_at(1_000_000_000, HEIGHT, 0x02);
        let utxo = MapUtxo::new(&[box_a.clone(), box_d.clone()]);

        let tx1 = spend_tx(&box_a, 1_000_000_000, HEIGHT);
        let tx2 = spend_tx_with_data_input(&box_d, &box_a, 1_000_000_000, HEIGHT);
        let snap = MempoolReadSnapshot::from_entries(vec![
            entry(&tx1, 10, 100, 0xA0),
            entry(&tx2, 10, 100, 0xB0),
        ]);

        let mut overlay = CandidateOverlay::new(&utxo);
        let params = ProtocolParams::mainnet_default();
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert_eq!(
            sel.checked.len(),
            2,
            "a data input on an in-block-spent box must still resolve",
        );
    }

    // ----- rent-claim conflict exclusion (feature end-to-end) -----

    /// secp256k1 generator point, compressed — a valid P2PK pubkey.
    const MINER_PK: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];

    #[test]
    fn pinned_rent_claim_excludes_conflicting_mempool_claim() {
        use crate::storage_rent_claim::build_rent_claim;
        // A real storage-rent self-claim, pinned ahead of selection,
        // excludes a fee-bearing mempool "bot" claim on the same box — the
        // feature's headline requirement, exercised end-to-end over the
        // overlay (build_rent_claim → apply_tx → select_user_txs).
        let mut params = ProtocolParams::mainnet_default();
        params.storage_period = 10; // box at h0, candidate h100 → eligible
        params.storage_fee_factor = 1_250_000;

        let rent_box = box_at(10_000_000_000, 0, 0x55);
        let utxo = MapUtxo::new(std::slice::from_ref(&rent_box));

        let claim = build_rent_claim(
            std::slice::from_ref(&rent_box),
            HEIGHT,
            &params,
            1,
            &MINER_PK,
        )
        .unwrap()
        .expect("aged box is claimable");

        // A bot's fee-bearing claim spending the SAME box.
        let bot = spend_tx(&rent_box, 9_000_000_000, HEIGHT);
        let snap = MempoolReadSnapshot::from_entries(vec![entry(&bot, 5_000_000, 100, 0xB0)]);

        let mut overlay = CandidateOverlay::new(&utxo);
        overlay.apply_tx(&claim.tx).unwrap(); // pin the rent claim first
        let sel = select_user_txs(
            &mut overlay,
            &snap,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();

        assert!(
            sel.checked.is_empty(),
            "a fee-bearing claim conflicting with the pinned rent claim must be excluded",
        );
    }
}
