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
//!   relay-priority order:
//!   skip any tx that double-spends an already-consumed box (this is how a
//!   pinned storage-rent self-claim excludes conflicting fee-bearing bot
//!   claims — seed the overlay with the rent tx first), skip any tx that
//!   fails revalidation against the candidate's frozen context, or would exceed
//!   the remaining block cost/size budget. Later fitting transactions retain
//!   their priority order and can still fill the block.
//!   This deliberately differs from Scala's `CandidateGenerator.collectTxs`,
//!   which stops at the first limit overflow; filling later entries is mining
//!   policy and does not change consensus validation.
//! - Block cost is summed exactly as the validator does: each tx is
//!   validated with its OWN fresh `CostAccumulator` (because `add` commits
//!   before checking the limit, a shared accumulator would be polluted by
//!   a rejected tx), and the per-tx `total_block_cost()` is folded into a
//!   running total compared against the budget.

use std::collections::{HashMap, HashSet};

use ergo_mempool::MempoolReadSnapshot;
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_ser::transaction::{read_transaction, transaction_id, write_transaction, Transaction};
use ergo_validation::{
    validate_transaction_parsed, CheckedTransaction, CostAccumulator, JitCost, ProtocolParams,
    ReemissionRuleInputs, TransactionContext, TxValidationCtx, TxValidationRules, UtxoView,
    INTERPRETER_INIT_COST,
};

use crate::error::{check_build_cancelled, MiningError};

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
        let tx_id = transaction_id(tx).map_err(|e| MiningError::IdComputation {
            op: "overlay_tx_id",
            reason: format!("{e:?}"),
        })?;
        self.apply_tx_with_id(tx, tx_id);
        Ok(())
    }

    /// Reuse the id already computed by consensus validation. Context-sensitive
    /// checks still run for every candidate; only immutable id work is reused.
    pub fn apply_checked(&mut self, checked: &CheckedTransaction) {
        self.apply_tx_with_id(
            checked.transaction(),
            ModifierId::from_bytes(*checked.tx_id()),
        );
    }

    fn apply_tx_with_id(&mut self, tx: &Transaction, tx_id: ModifierId) {
        for input in &tx.inputs {
            self.spent_in_block.insert(input.box_id);
        }
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

/// Validate caller-supplied transactions in their original dependency order.
/// This is a block-building path, so no relay fee or mempool admission policy
/// applies. Invalid, conflicting and oversized transactions are skipped;
/// descendants can only resolve when their parent was actually included.
#[allow(clippy::too_many_arguments)]
pub fn select_prioritized_txs_cancellable(
    overlay: &mut CandidateOverlay,
    transactions: &[Transaction],
    ctx: &TransactionContext,
    params: &ProtocolParams,
    last_headers: &[Header],
    cost_budget: u64,
    size_budget: u64,
    reemission_rules: Option<&ReemissionRuleInputs>,
    should_cancel: &dyn Fn() -> bool,
) -> Result<Selected, MiningError> {
    let block_cap = JitCost::from_block_cost(params.max_block_cost).map_err(|e| {
        MiningError::IdComputation {
            op: "priority_block_cap",
            reason: format!("{e:?}"),
        }
    })?;
    let mut selected = Selected::default();
    let minimum_tx_cost = INTERPRETER_INIT_COST
        .saturating_add(params.input_cost)
        .saturating_add(params.output_cost);
    for tx in transactions {
        check_build_cancelled(should_cancel)?;
        let remaining_cost = cost_budget.saturating_sub(selected.total_cost);
        if remaining_cost < minimum_tx_cost {
            break;
        }
        let structural_cost = INTERPRETER_INIT_COST
            .saturating_add((tx.inputs.len() as u64).saturating_mul(params.input_cost))
            .saturating_add((tx.data_inputs.len() as u64).saturating_mul(params.data_input_cost))
            .saturating_add((tx.output_candidates.len() as u64).saturating_mul(params.output_cost));
        if structural_cost > remaining_cost {
            continue;
        }
        if tx
            .inputs
            .iter()
            .any(|input| overlay.is_spent(&input.box_id))
        {
            continue;
        }
        let mut writer = VlqWriter::new();
        if write_transaction(&mut writer, tx).is_err() {
            continue;
        }
        let bytes = writer.result();
        if selected.total_size.saturating_add(bytes.len() as u64) > size_budget {
            continue;
        }
        let Some((inputs, data_inputs)) = overlay.resolve_tx(tx) else {
            continue;
        };
        check_build_cancelled(should_cancel)?;
        let mut cost = CostAccumulator::new(block_cap);
        let mut validation = TxValidationCtx {
            ctx,
            params,
            cost: &mut cost,
            last_headers,
            rules: TxValidationRules {
                reemission: reemission_rules,
            },
        };
        let Ok(checked) = validate_transaction_parsed(
            tx.clone(),
            &bytes,
            inputs,
            data_inputs,
            false,
            &mut validation,
        ) else {
            continue;
        };
        check_build_cancelled(should_cancel)?;
        let tx_cost = cost.total_block_cost();
        if selected.total_cost.saturating_add(tx_cost) > cost_budget {
            continue;
        }
        overlay.apply_checked(&checked);
        selected.total_cost = selected.total_cost.saturating_add(tx_cost);
        selected.total_size = selected.total_size.saturating_add(bytes.len() as u64);
        selected.checked.push((checked, tx_cost));
    }
    Ok(selected)
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
/// pinned txs (and a safety gap). Transactions that do not fit, conflict, fail
/// to resolve, or fail revalidation are skipped. A skipped parent's descendants
/// cannot resolve its outputs, while later independent transactions can fit.
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
    select_user_txs_cancellable(
        overlay,
        snapshot,
        ctx,
        params,
        last_headers,
        cost_budget,
        size_budget,
        reemission_rules,
        &|| false,
    )
}

/// Selection with cooperative cancellation at transaction boundaries. A newer
/// mempool snapshot on the same parent must not cancel this pass: its validated
/// result can still be published while the next refresh waits.
#[allow(clippy::too_many_arguments)]
pub fn select_user_txs_cancellable(
    overlay: &mut CandidateOverlay,
    snapshot: &MempoolReadSnapshot,
    ctx: &TransactionContext,
    params: &ProtocolParams,
    last_headers: &[Header],
    cost_budget: u64,
    size_budget: u64,
    reemission_rules: Option<&ReemissionRuleInputs>,
    should_cancel: &dyn Fn() -> bool,
) -> Result<Selected, MiningError> {
    check_build_cancelled(should_cancel)?;
    if cost_budget == 0 || size_budget == 0 {
        return Ok(Selected::default());
    }
    let block_cap = JitCost::from_block_cost(params.max_block_cost).map_err(|e| {
        MiningError::IdComputation {
            op: "select_block_cap",
            reason: format!("{e:?}"),
        }
    })?;

    let mut sel = Selected::default();
    // Every valid tx has at least one input and output, and scripts are on.
    // Entry::cost is an observation at admission, not a lower bound: a changed
    // context can take a cheaper script branch or change voted cost parameters.
    let minimum_tx_cost = INTERPRETER_INIT_COST
        .saturating_add(params.input_cost)
        .saturating_add(params.output_cost);

    for entry in snapshot.iter() {
        check_build_cancelled(should_cancel)?;
        let remaining_cost = cost_budget.saturating_sub(sel.total_cost);
        if remaining_cost < minimum_tx_cost {
            // No later valid transaction can fit, even with a cheaper script.
            break;
        }
        // A large priority entry must not block smaller independent entries.
        if sel.total_size.saturating_add(u64::from(entry.size_bytes)) > size_budget {
            continue;
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
        check_build_cancelled(should_cancel)?;

        // The structural part of compute_tx_init_cost is a candidate-context
        // floor. Token access and script/proof costs can only add to it. Skip
        // before UTXO resolution and validation, leaving later cheap txs eligible.
        let structural_cost = INTERPRETER_INIT_COST
            .saturating_add((tx.inputs.len() as u64).saturating_mul(params.input_cost))
            .saturating_add((tx.data_inputs.len() as u64).saturating_mul(params.data_input_cost))
            .saturating_add((tx.output_candidates.len() as u64).saturating_mul(params.output_cost));
        if structural_cost > remaining_cost {
            continue;
        }

        // Resolve inputs/data-inputs against the evolving overlay. A None
        // means an input is already spent in-block or not yet available
        // (e.g. a child whose parent was not included) — skip the tx.
        let Some(resolved_inputs) = overlay.resolve_inputs(&tx) else {
            continue;
        };
        let Some(resolved_data_inputs) = overlay.resolve_data_inputs(&tx) else {
            continue;
        };
        check_build_cancelled(should_cancel)?;

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
            #[cfg(test)]
            tests::VALIDATION_CALLS.with(|calls| calls.set(calls.get() + 1));
            match validate_transaction_parsed(
                tx,
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
        check_build_cancelled(should_cancel)?;

        // Validation used a fresh accumulator and has not touched the overlay.
        // A budget skip is a fit decision, never a consensus-invalid suspect.
        let tx_cost = cost.total_block_cost();
        if sel.total_cost.saturating_add(tx_cost) > cost_budget {
            continue;
        }

        overlay.apply_checked(&checked);
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
    use ergo_ser::opcode::{Expr, IrNode, Payload};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_ser::transaction::write_transaction;

    thread_local! {
        pub(super) static VALIDATION_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Reproducible selection workload; run explicitly with --ignored --nocapture.
    #[test]
    #[ignore = "selection measurement"]
    fn measure_cost_exhausted_snapshot() {
        let boxes: Vec<_> = (0u64..1000)
            .map(|index| {
                let mut b = box_at(1_000_000_000, HEIGHT, 0);
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&index.to_be_bytes());
                b.transaction_id = ModifierId::from_bytes(id);
                b
            })
            .collect();
        let utxo = MapUtxo::new(&boxes);
        let entries: Vec<_> = boxes
            .iter()
            .map(|b| {
                let tx = spend_tx(b, 1_000_000_000, HEIGHT);
                let mut e = wire_entry(&tx, 0, 0);
                e.tx_id = Digest32::from_bytes(*transaction_id(&tx).unwrap().as_bytes());
                e
            })
            .collect();
        let params = ProtocolParams::mainnet_default();
        let probe = MempoolReadSnapshot::from_entries(vec![entries[0].clone()]);
        let budget = select_user_txs(
            &mut CandidateOverlay::new(&utxo),
            &probe,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap()
        .total_cost
            + 1;
        let snapshot = MempoolReadSnapshot::from_entries(entries);
        const PASSES: usize = 100;
        VALIDATION_CALLS.with(|calls| calls.set(0));
        let start = std::time::Instant::now();
        for _ in 0..PASSES {
            let selected = select_user_txs(
                &mut CandidateOverlay::new(&utxo),
                &snapshot,
                &ctx(),
                &params,
                &[],
                budget,
                u64::MAX,
                None,
            )
            .unwrap();
            assert_eq!(selected.checked.len(), 1);
            assert_eq!(budget - selected.total_cost, 1);
            assert!(selected.suspects.is_empty());
        }
        let elapsed = start.elapsed();
        let calls = VALIDATION_CALLS.with(|calls| calls.get());
        println!("1000 independent valid trivial-script txs; {PASSES} passes; budget={budget}; remaining=1; validation_calls/pass={}; elapsed={elapsed:?}; time/pass={:?}", calls / PASSES, elapsed / PASSES as u32);
    }

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
            reserved_header_bits: 0,
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

    #[test]
    fn parent_change_during_resolution_stops_before_applying_transaction() {
        struct CancelOnRead {
            base: MapUtxo,
            cancelled: std::cell::Cell<bool>,
            reads: std::cell::Cell<usize>,
        }
        impl UtxoView for CancelOnRead {
            fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
                self.reads.set(self.reads.get() + 1);
                self.cancelled.set(true);
                self.base.get_box(id)
            }
        }
        let input = box_at(1_000_000_000, HEIGHT, 1);
        let next_input = box_at(1_000_000_000, HEIGHT, 2);
        let tx = spend_tx(&input, 1_000_000_000, HEIGHT);
        let next_tx = spend_tx(&next_input, 1_000_000_000, HEIGHT);
        let utxo = CancelOnRead {
            base: MapUtxo::new(&[input.clone(), next_input]),
            cancelled: std::cell::Cell::new(false),
            reads: std::cell::Cell::new(0),
        };
        let snapshot = MempoolReadSnapshot::from_entries(vec![
            entry(&tx, 1, 100, 0xA0),
            entry(&next_tx, 1, 100, 0xB0),
        ]);
        let mut overlay = CandidateOverlay::new(&utxo);
        let result = select_user_txs_cancellable(
            &mut overlay,
            &snapshot,
            &ctx(),
            &ProtocolParams::mainnet_default(),
            &[],
            u64::MAX,
            u64::MAX,
            None,
            &|| utxo.cancelled.get(),
        );
        assert!(matches!(result, Err(MiningError::BuildCancelled)));
        assert_eq!(
            utxo.reads.get(),
            1,
            "the next transaction must not be resolved"
        );
        assert!(!overlay.is_spent(&input.box_id().unwrap()));
        assert!(overlay.in_block_outputs.is_empty());
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
    fn size_budget_limits_included_transactions() {
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

        assert_eq!(
            sel.checked.len(),
            2,
            "only two transactions fit the size budget"
        );
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

    /// Three priority-ordered transactions: a large parent, its small child,
    /// and a small independent spend. Sizes are their actual wire lengths.
    fn non_fitting_parent_family() -> (MapUtxo, Transaction, Transaction, Transaction) {
        let parent_input = box_at(1_000_000_000, HEIGHT, 1);
        let independent_input = box_at(1_000_000_000, HEIGHT, 2);
        let mut parent = spend_tx(&parent_input, 250_000_000, HEIGHT);
        parent.output_candidates = vec![parent.output_candidates[0].clone(); 4];
        let parent_output = ErgoBox {
            candidate: parent.output_candidates[0].clone(),
            transaction_id: transaction_id(&parent).unwrap(),
            index: 0,
        };
        let child = spend_tx(&parent_output, 250_000_000, HEIGHT);
        let independent = spend_tx(&independent_input, 1_000_000_000, HEIGHT);
        (
            MapUtxo::new(&[parent_input, independent_input]),
            parent,
            child,
            independent,
        )
    }

    fn wire_entry(tx: &Transaction, fee: u64, seed: u8) -> Entry {
        entry(tx, fee, tx_bytes(tx).len() as u32, seed)
    }

    /// Use the production admission validator so the estimate is observed cost,
    /// in the same units and fresh accumulator used by real mempool admission.
    fn admitted_entry(tx: &Transaction, utxo: &MapUtxo, context: &TransactionContext) -> Entry {
        use ergo_mempool::Validator;
        let params = ProtocolParams::mainnet_default();
        let mut cost = CostAccumulator::new(JitCost::from_block_cost(4_900_000).unwrap());
        let validated = ergo_mempool::ErgoValidator
            .validate(
                &tx_bytes(tx),
                utxo,
                utxo,
                &mut TxValidationCtx {
                    ctx: context,
                    params: &params,
                    cost: &mut cost,
                    last_headers: &[],
                    rules: TxValidationRules { reemission: None },
                },
            )
            .unwrap();
        let mut e = wire_entry(tx, 0, 0);
        e.tx_id = validated.tx_id;
        e.cost = validated.consumed_cost;
        e
    }

    /// Always true, with a short branch at fast_height and extra work elsewhere.
    fn context_cost_box(fast_height: u32) -> ErgoBox {
        let height = || {
            Expr::Op(IrNode {
                opcode: 0xA3,
                payload: Payload::Zero,
            })
        };
        let binary = |opcode, left, right| {
            Expr::Op(IrNode {
                opcode,
                payload: Payload::Two(Box::new(left), Box::new(right)),
            })
        };
        let fast = binary(
            0x93,
            height(),
            Expr::Const {
                tpe: SigmaType::SInt,
                val: SigmaValue::Int(fast_height as i32),
            },
        );
        let mut slow = binary(0x93, height(), height());
        for _ in 0..16 {
            slow = binary(0xED, binary(0x93, height(), height()), slow);
        }
        let mut b = box_at(1_000_000_000, HEIGHT, 1);
        let mut tree = trivial_tree();
        tree.body = Expr::Op(IrNode {
            opcode: 0xD1,
            payload: Payload::One(Box::new(binary(0xEC, fast, slow))),
        });
        b.candidate = ErgoBoxCandidate::new(
            1_000_000_000,
            tree,
            HEIGHT,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        b
    }

    #[test]
    fn exhausted_cost_skips_remaining_admission_costs_without_validation() {
        let boxes: Vec<_> = (1..=3)
            .map(|seed| box_at(1_000_000_000, HEIGHT, seed))
            .collect();
        let utxo = MapUtxo::new(&boxes);
        let entries: Vec<_> = boxes
            .iter()
            .map(|b| admitted_entry(&spend_tx(b, 1_000_000_000, HEIGHT), &utxo, &ctx()))
            .collect();
        let budget = entries[0].cost + 1;
        assert!(entries.iter().skip(1).all(|e| e.cost > 1));
        let snapshot = MempoolReadSnapshot::from_entries(entries);
        let mut overlay = CandidateOverlay::new(&utxo);
        VALIDATION_CALLS.with(|calls| calls.set(0));
        let selected = select_user_txs(
            &mut overlay,
            &snapshot,
            &ctx(),
            &ProtocolParams::mainnet_default(),
            &[],
            budget,
            u64::MAX,
            None,
        )
        .unwrap();
        assert_eq!(VALIDATION_CALLS.with(|calls| calls.get()), 1);
        assert_eq!(selected.checked.len(), 1);
        assert_eq!(budget - selected.total_cost, 1);
        assert!(selected.suspects.is_empty());
        assert!(!overlay.is_spent(&boxes[1].box_id().unwrap()));
        assert!(!overlay.is_spent(&boxes[2].box_id().unwrap()));
    }

    #[test]
    fn admission_cost_that_fits_still_uses_exact_candidate_cost_check() {
        let b = context_cost_box(HEIGHT);
        let utxo = MapUtxo::new(std::slice::from_ref(&b));
        let tx = spend_tx(&b, 1_000_000_000, HEIGHT);
        let mut candidate_ctx = ctx();
        candidate_ctx.height += 1;
        let e = admitted_entry(&tx, &utxo, &ctx());
        let budget = e.cost;
        assert!(admitted_entry(&tx, &utxo, &candidate_ctx).cost > budget);
        let snapshot = MempoolReadSnapshot::from_entries(vec![e]);
        let mut overlay = CandidateOverlay::new(&utxo);
        VALIDATION_CALLS.with(|calls| calls.set(0));
        let selected = select_user_txs(
            &mut overlay,
            &snapshot,
            &candidate_ctx,
            &ProtocolParams::mainnet_default(),
            &[],
            budget,
            u64::MAX,
            None,
        )
        .unwrap();
        assert_eq!(VALIDATION_CALLS.with(|calls| calls.get()), 1);
        assert!(selected.checked.is_empty());
        assert_eq!(selected.total_cost, 0);
        assert!(selected.suspects.is_empty());
        assert!(!overlay.is_spent(&b.box_id().unwrap()));
        assert!(overlay.in_block_outputs.is_empty());
    }

    #[test]
    fn higher_admission_cost_does_not_skip_a_cheaper_candidate_context() {
        let b = context_cost_box(HEIGHT + 1);
        let utxo = MapUtxo::new(std::slice::from_ref(&b));
        let tx = spend_tx(&b, 1_000_000_000, HEIGHT);
        let mut candidate_ctx = ctx();
        candidate_ctx.height += 1;
        let e = admitted_entry(&tx, &utxo, &ctx());
        let budget = admitted_entry(&tx, &utxo, &candidate_ctx).cost;
        assert!(
            e.cost > budget,
            "a raw admission-cost filter would falsely skip"
        );
        let snapshot = MempoolReadSnapshot::from_entries(vec![e]);
        VALIDATION_CALLS.with(|calls| calls.set(0));
        let selected = select_user_txs(
            &mut CandidateOverlay::new(&utxo),
            &snapshot,
            &candidate_ctx,
            &ProtocolParams::mainnet_default(),
            &[],
            budget,
            u64::MAX,
            None,
        )
        .unwrap();
        assert_eq!(VALIDATION_CALLS.with(|calls| calls.get()), 1);
        assert_eq!(selected.checked.len(), 1);
        assert_eq!(selected.total_cost, budget);
        assert!(selected.suspects.is_empty());
    }

    #[test]
    fn structural_cost_skip_does_not_validate_and_keeps_later_cheap_entry() {
        let (utxo, expensive, _, cheap) = non_fitting_parent_family();
        let expensive_entry = admitted_entry(&expensive, &utxo, &ctx());
        let cheap_entry = admitted_entry(&cheap, &utxo, &ctx());
        let budget = cheap_entry.cost;
        assert!(expensive_entry.cost > budget);
        let snapshot = MempoolReadSnapshot::from_entries(vec![expensive_entry, cheap_entry]);
        let mut overlay = CandidateOverlay::new(&utxo);
        VALIDATION_CALLS.with(|calls| calls.set(0));
        let selected = select_user_txs(
            &mut overlay,
            &snapshot,
            &ctx(),
            &ProtocolParams::mainnet_default(),
            &[],
            budget,
            u64::MAX,
            None,
        )
        .unwrap();
        assert_eq!(VALIDATION_CALLS.with(|calls| calls.get()), 1);
        assert_eq!(selected.checked.len(), 1);
        assert_eq!(
            selected.checked[0].0.tx_id(),
            transaction_id(&cheap).unwrap().as_bytes()
        );
        assert_eq!(selected.total_cost, budget);
        assert!(selected.suspects.is_empty());
        assert!(!overlay.is_spent(&expensive.inputs[0].box_id));
        assert!(overlay.is_spent(&cheap.inputs[0].box_id));
    }

    #[test]
    fn structural_floor_equality_reaches_exact_check() {
        let b = box_at(1_000_000_000, HEIGHT, 1);
        let utxo = MapUtxo::new(std::slice::from_ref(&b));
        let tx = spend_tx(&b, 1_000_000_000, HEIGHT);
        let e = admitted_entry(&tx, &utxo, &ctx());
        let params = ProtocolParams::mainnet_default();
        let budget = INTERPRETER_INIT_COST + params.input_cost + params.output_cost;
        assert!(e.cost > budget, "script work exceeds the structural floor");
        let snapshot = MempoolReadSnapshot::from_entries(vec![e]);
        VALIDATION_CALLS.with(|calls| calls.set(0));
        let selected = select_user_txs(
            &mut CandidateOverlay::new(&utxo),
            &snapshot,
            &ctx(),
            &params,
            &[],
            budget,
            u64::MAX,
            None,
        )
        .unwrap();
        assert_eq!(VALIDATION_CALLS.with(|calls| calls.get()), 1);
        assert!(selected.checked.is_empty());
        assert!(selected.suspects.is_empty());
    }

    #[test]
    fn cost_floors_use_current_candidate_parameters() {
        let b = box_at(1_000_000_000, HEIGHT, 1);
        let utxo = MapUtxo::new(std::slice::from_ref(&b));
        let tx = spend_tx(&b, 1_000_000_000, HEIGHT);
        let e = admitted_entry(&tx, &utxo, &ctx());
        let admission_cost = e.cost;
        let snapshot = MempoolReadSnapshot::from_entries(vec![e]);
        let mut params = ProtocolParams::mainnet_default();
        params.input_cost = 0;
        params.output_cost = 0;
        let probe = select_user_txs(
            &mut CandidateOverlay::new(&utxo),
            &snapshot,
            &ctx(),
            &params,
            &[],
            u64::MAX,
            u64::MAX,
            None,
        )
        .unwrap();
        assert_eq!(probe.checked.len(), 1);
        let budget = probe.total_cost;
        assert!(admission_cost > budget);
        VALIDATION_CALLS.with(|calls| calls.set(0));
        let selected = select_user_txs(
            &mut CandidateOverlay::new(&utxo),
            &snapshot,
            &ctx(),
            &params,
            &[],
            budget,
            u64::MAX,
            None,
        )
        .unwrap();
        assert_eq!(VALIDATION_CALLS.with(|calls| calls.get()), 1);
        assert_eq!(selected.checked.len(), 1);
        assert_eq!(selected.total_cost, budget);
    }

    #[test]
    fn size_skip_keeps_later_small_independent_transaction_and_excludes_descendant() {
        let (utxo, parent, child, independent) = non_fitting_parent_family();
        let budget = tx_bytes(&independent).len() as u64;
        assert!(tx_bytes(&parent).len() as u64 > budget);
        assert!(tx_bytes(&child).len() as u64 <= budget);
        let snapshot = MempoolReadSnapshot::from_entries(vec![
            wire_entry(&parent, 500, 0xA0),
            wire_entry(&child, 400, 0xB0),
            wire_entry(&independent, 100, 0xC0),
        ]);
        let mut overlay = CandidateOverlay::new(&utxo);
        let selected = select_user_txs(
            &mut overlay,
            &snapshot,
            &ctx(),
            &ProtocolParams::mainnet_default(),
            &[],
            u64::MAX,
            budget,
            None,
        )
        .unwrap();
        assert_eq!(selected.checked.len(), 1);
        assert_eq!(
            selected.checked[0].0.tx_id(),
            transaction_id(&independent).unwrap().as_bytes()
        );
        assert_eq!(selected.total_size, budget);
        assert!(selected.suspects.is_empty());
        assert!(!overlay.is_spent(&parent.inputs[0].box_id));
        assert!(overlay.is_spent(&independent.inputs[0].box_id));
    }

    #[test]
    fn cost_skip_keeps_later_cheap_independent_transaction_and_excludes_descendant() {
        let (utxo, parent, child, independent) = non_fitting_parent_family();
        let params = ProtocolParams::mainnet_default();
        let measured_cost = |tx: &Transaction| {
            let mut overlay = CandidateOverlay::new(&utxo);
            let snapshot = MempoolReadSnapshot::from_entries(vec![wire_entry(tx, 0, 0xFF)]);
            let selected = select_user_txs(
                &mut overlay,
                &snapshot,
                &ctx(),
                &params,
                &[],
                u64::MAX,
                u64::MAX,
                None,
            )
            .unwrap();
            assert_eq!(
                selected.checked.len(),
                1,
                "cost probe must fully validate its transaction"
            );
            selected.total_cost
        };
        let budget = measured_cost(&independent);
        assert!(
            measured_cost(&parent) > budget,
            "the first transaction is valid but more expensive"
        );
        let snapshot = MempoolReadSnapshot::from_entries(vec![
            wire_entry(&parent, 500, 0xA0),
            wire_entry(&child, 400, 0xB0),
            wire_entry(&independent, 100, 0xC0),
        ]);
        let mut overlay = CandidateOverlay::new(&utxo);
        let selected = select_user_txs(
            &mut overlay,
            &snapshot,
            &ctx(),
            &params,
            &[],
            budget,
            u64::MAX,
            None,
        )
        .unwrap();
        assert_eq!(selected.checked.len(), 1);
        assert_eq!(
            selected.checked[0].0.tx_id(),
            transaction_id(&independent).unwrap().as_bytes()
        );
        assert_eq!(selected.total_cost, budget);
        assert!(
            selected.suspects.is_empty(),
            "fit skips and unresolved descendants remain in the mempool"
        );
        assert!(!overlay.is_spent(&parent.inputs[0].box_id));
        assert!(overlay.is_spent(&independent.inputs[0].box_id));
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
            None,
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
