//! Block candidate orchestrator.
//!
//! Implements v12 §5 of the design plan: composes pre-header freeze,
//! transaction selection, coinbase + reemission dispatch,
//! `candidate_dry_run`, parent-id guard, header assembly, and work-message
//! construction.
//!
//! Scope / invariants:
//! - The block carries the coinbase (emission) tx, then mempool user
//!   transactions selected over an in-block overlay, then a single
//!   fee-collecting tx — block order `[emission, ...user txs, fee]`. A fee
//!   tx is emitted only when an included user tx produces a fee-proposition
//!   output.
//! - Cost and size are enforced at selection so the assembled block stays
//!   under the voted `max_block_cost` / `max_block_size`; the AVL dry-run
//!   computes only the state root + proof and checks neither.
//! - Mainnet post-EIP-27 emission only. Pre-activation and at-activation
//!   paths exist in `reemission` for completeness but mainnet is far past
//!   activation.
//! - Non-epoch-boundary heights only. Epoch-boundary candidate
//!   construction is deferred (the proposed-update + validation-settings
//!   extension encoding isn't implemented).

/// Wall-clock cost of the expensive `generate_candidate` phases, measured per
/// build and surfaced on the engine's build-complete log line. Millisecond
/// granularity — these phases run 10²–10⁴ ms on a cold full-archival store.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseTimings {
    /// Phases 8–9: emission tx build + validation.
    pub emission_ms: u64,
    /// Phase 9c: storage-rent claim build (0 when rent disabled/empty).
    pub rent_ms: u64,
    /// Phases 9d–9e: mempool selection + per-tx re-validation + fee-tx trim.
    pub select_ms: u64,
    /// Phase 10: AVL+ dry-run (new_state_root + proof bytes) — the report's
    /// prime cost suspect.
    pub dryrun_ms: u64,
    /// Phase 12: tx/witness-id derivation + transactions/extension roots.
    pub roots_ms: u64,
}

use ergo_crypto::difficulty::{
    epoch_length_for_height, get_target, next_n_bits, previous_heights_for_recalculation,
    DifficultyParams,
};
use ergo_crypto::merkle::{extension_root, transactions_root};
use ergo_mempool::MempoolReadSnapshot;
use ergo_primitives::digest::{blake2b256, Digest32};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::{read_header, serialize_header_without_pow, Header};
use ergo_ser::transaction::{bytes_to_sign, write_transaction, Transaction};
use ergo_validation::popow::algos::unpack_interlinks;
use ergo_validation::{
    validate_transaction_parsed, voting::derive_activated_script_version, CheckedTransaction,
    CostAccumulator, JitCost, ProtocolParams, TransactionContext, TxValidationCtx, UtxoView,
};
use num_bigint::BigUint;

use crate::candidate_selection::{select_user_txs, CandidateOverlay};
use crate::coinbase::{build_fee_tx, build_pre_eip27_emission_tx};
use crate::emission_box::lookup_emission_box_from_parent;
use crate::emission_rules::MonetarySettings;
use crate::error::MiningError;
use crate::extension_builder::{build_candidate_extension_fields, is_epoch_boundary_mainnet};
use crate::reemission::{build_post_eip27_emission_tx, ReemissionSettings};
use crate::state_view::CandidateStateView;
use crate::storage_rent_claim::build_budget_bounded_rent_claim;
use crate::tx_selection::DEFAULT_COST_SAFETY_GAP;
use crate::work_message::WorkMessage;
use ergo_validation::pre_header::{
    build_last_block_utxo_root, CandidatePreHeader, CandidateValidationContext,
};

/// Cached state for a generated candidate. Wraps everything the
/// solution path needs to assemble a `FullBlock`.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Assembled header with placeholder Autolykos solution. The
    /// solution path patches in `(pk, n)` and re-serializes.
    pub header: Header,
    /// Frozen script-visible context. Same `pre_header.*`,
    /// `last_headers`, `last_block_utxo_root` that validated the
    /// candidate's transactions during generation. Stored so the
    /// solution path can re-validate symbolically if needed.
    pub validation_ctx: CandidateValidationContext,
    /// Raw transactions in the candidate's BlockTransactions section.
    /// CheckedTransactions aren't Clone, so we keep the raw form and
    /// re-validate on solution submission if a CheckedBlock is needed.
    pub transactions: Vec<Transaction>,
    /// Raw AVL+ proof bytes captured from the dry-run. Wraps with the
    /// header id at FullBlock-assembly time to produce the ADProofs
    /// section.
    pub ad_proof_bytes: Vec<u8>,
    /// Extension fields (key/value byte pairs), already packed via
    /// `extension_builder`.
    pub extension_fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// `blake2b256(serialize_header_without_pow(header))` — the
    /// external miner hashes this with their nonce.
    pub msg: [u8; 32],
    /// Mining target. The miner's hit must be `<= target` to count
    /// as a valid solution.
    pub target: BigUint,
    /// Frozen `chain_state().best_full_block_id` at generation time.
    /// The solution-path API + executor compare this against the live
    /// best-full-block id to reject candidates whose parent the chain
    /// has moved past.
    pub parent_id: [u8; 32],
}

/// Build a candidate for the next block. Returns `None` if the chain
/// has not reached a state from which mining is possible (tip below
/// height 10, or a tip-flip caught by the post-dry-run guard).
///
/// **Synced-tip contract** (v12 §0 row 2): the caller is expected to
/// have gated on `synced(tip)` already. Mining at an unsynced tip
/// produces script-divergent candidates and is forbidden.
///
/// `mempool` supplies the priority-ordered snapshot from which user
/// transactions are selected (placed after the coinbase tx, before the
/// fee-collecting tx).
///
/// `eligible_rent_boxes` are storage-rent-eligible boxes (resolved from
/// state by the caller, oldest-first, already capped) the miner
/// self-claims with no fee. The claim is pinned ahead of mempool selection
/// so any conflicting fee-bearing claim on the same box is excluded. An
/// empty slice disables rent collection.
pub fn generate_candidate<V: CandidateStateView>(
    view: &V,
    mempool: MempoolReadSnapshot,
    miner_pk: &[u8; 33],
    monetary: &MonetarySettings,
    reemission: Option<&ReemissionSettings>,
    chain_config: &DifficultyParams,
    eligible_rent_boxes: &[ErgoBox],
) -> Result<Option<(Candidate, WorkMessage, PhaseTimings)>, MiningError> {
    // 1. Tip + parent header (all reads via one committed view — see
    //    `CandidateStateView`; the snapshot impl sources them from a single
    //    redb read txn so the whole build is one consistent committed view).
    let parent_id: [u8; 32] = view.best_full_block_id();
    let parent_height = view.best_full_block_height();
    let candidate_height = parent_height + 1;
    let mut timings = PhaseTimings::default();

    if is_epoch_boundary_mainnet(candidate_height) {
        return Err(MiningError::InvalidConfig(format!(
            "epoch-boundary candidate at h={candidate_height} not supported in v1 \
             (proposed-update + validation-settings encoding deferred)"
        )));
    }

    let parent_header_bytes = view
        .get_header_bytes(&parent_id)
        .map_err(state_err)?
        .ok_or_else(|| MiningError::StateRead {
            op: "load_parent_header",
            reason: format!(
                "best_full_block_id {} not in HEADERS",
                hex::encode(parent_id)
            ),
        })?;
    let parent_header = {
        let mut r = VlqReader::new(&parent_header_bytes);
        read_header(&mut r).map_err(|e| MiningError::Decode {
            op: "parent_header",
            reason: format!("{e:?}"),
        })?
    };

    // 2. Snapshot params + applied-chain window
    let (active_params, validation_settings) = view.tip_snapshot_params().map_err(state_err)?;
    let last_headers = view.last_applied_chain_window_10().map_err(state_err)?;

    // 3. Difficulty retarget (or parent's nBits when non-recalc)
    let epoch_len = epoch_length_for_height(candidate_height, chain_config);
    let needed_heights = previous_heights_for_recalculation(candidate_height, epoch_len);
    let epoch_headers = load_epoch_headers(view, &needed_heights, &parent_header)?;
    let new_n_bits = next_n_bits(candidate_height, &epoch_headers, chain_config).map_err(|e| {
        MiningError::IdComputation {
            op: "difficulty_retarget",
            reason: e.to_string(),
        }
    })?;

    // 4. Timestamp: clamped monotonic.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(parent_header.timestamp + 1);
    let timestamp = std::cmp::max(now_ms, parent_header.timestamp + 1);

    // 5. Build pre-header.
    let pre_header = CandidatePreHeader {
        version: active_params.block_version,
        parent_id,
        height: candidate_height,
        timestamp,
        n_bits: new_n_bits,
        votes: [0u8; 3], // v1: neutral votes
        miner_pubkey: *miner_pk,
    };

    // 6. Activated script version + last_block_utxo_root.
    let activated_script_version = derive_activated_script_version(pre_header.version);
    let last_block_utxo_root = build_last_block_utxo_root(parent_header.state_root);

    let validation_ctx = CandidateValidationContext {
        pre_header: pre_header.clone(),
        activated_script_version,
        last_headers: last_headers.clone(),
        last_block_utxo_root,
    };

    // 7. Build extension fields (non-epoch path: interlinks-only).
    let parent_extension_bytes = read_parent_extension_bytes(view, &parent_header)?;
    let parent_interlinks = unpack_interlinks_from_extension(&parent_extension_bytes)?;
    // A non-genesis parent must carry interlinks; an empty set means its stored
    // extension is malformed or missing them. Fail the build with a typed error
    // here rather than panicking the engine task downstream (`update_interlinks`
    // asserts a non-empty interlinks vector for a non-genesis header).
    if *parent_header.parent_id.as_bytes() != [0u8; 32] && parent_interlinks.is_empty() {
        return Err(MiningError::Decode {
            op: "parent_interlinks",
            reason: "non-genesis parent extension carries no interlinks fields".into(),
        });
    }
    let extension_fields = build_candidate_extension_fields(
        &parent_header,
        &parent_interlinks,
        candidate_height,
        crate::extension_builder::MAINNET_VOTING_LENGTH,
    )?;

    // 8. Coinbase: emission tx. Three regimes:
    //   - reemission = Some + height > activation_height: post-EIP-27,
    //     one input, deducts reemission tokens per block (mainnet
    //     regime since h=777_217).
    //   - reemission = Some + height <= activation_height: pre-EIP-27
    //     emission tx (mainnet pre-777_217 history; not exercised in
    //     practice now that mainnet is past activation).
    //   - reemission = None: network has no EIP-27 protocol (new
    //     public testnet); always pre-EIP-27 emission tx.
    let phase_start = std::time::Instant::now();
    let emission_box = lookup_emission_box_from_parent(view, &parent_id, &parent_header)?;
    let emission_tx = match reemission {
        Some(reem) if candidate_height > reem.activation_height => {
            build_post_eip27_emission_tx(&emission_box, miner_pk, candidate_height, monetary, reem)?
        }
        _ => build_pre_eip27_emission_tx(&emission_box, miner_pk, candidate_height, monetary)?,
    };

    // 9. Validate the emission (coinbase) tx → CheckedTransaction, using the
    //    live voted params (from_active) so cost / min-value / storage
    //    params match the validator that judges the submitted block.
    let block_cap = JitCost::from_block_cost(active_params.max_block_cost as u64).map_err(|e| {
        MiningError::IdComputation {
            op: "max_block_cost_to_jit",
            reason: format!("{e:?}"),
        }
    })?;
    let params = ProtocolParams::from_active(&active_params);
    let ctx = TransactionContext {
        height: candidate_height,
        miner_pubkey: *miner_pk,
        pre_header_timestamp: timestamp,
        activated_script_version,
        pre_header_version: pre_header.version,
        pre_header_parent_id: parent_id,
        pre_header_n_bits: new_n_bits as u64,
        pre_header_votes: [0u8; 3],
    };

    let emission_bytes = serialize_tx(&emission_tx, "serialize_emission_tx")?;
    let emission_size = emission_bytes.len() as u64;
    let mut emission_cost_acc = CostAccumulator::new(block_cap);
    let checked_emission = {
        let mut tx_ctx = TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut emission_cost_acc,
            last_headers: last_headers.as_slice(),
        };
        validate_transaction_parsed(
            emission_tx.clone(),
            &emission_bytes,
            vec![emission_box.clone()],
            Vec::new(),
            false,
            &mut tx_ctx,
        )
        .map_err(|e| MiningError::IdComputation {
            op: "validate_emission_tx",
            reason: format!("{e:?}"),
        })?
    };
    let emission_cost = emission_cost_acc.total_block_cost();
    timings.emission_ms = phase_start.elapsed().as_millis() as u64;

    // 9b. Seed an in-block overlay (over the committed state tip — the same
    //     base view the submit-time validator uses) with the emission tx.
    let base: &dyn UtxoView = view;
    let mut overlay = CandidateOverlay::new(base);
    overlay.apply_tx(&emission_tx)?;

    // 9c. Pinned storage-rent self-claim, sized to FILL the block budget.
    //     Sweep the oldest eligible boxes into a claim bounded by the block
    //     cost/size budget (after the coinbase, reserving ~1/16 of the block
    //     for fee-paying user txs), so the pinned [coinbase, rent] prefix can
    //     never exceed max_block_cost / max_block_size — only the block caps
    //     gate a self-mined tx (no consensus per-tx size limit; per-tx counts
    //     cap at 32_767, far above what fits). The claim is applied to the
    //     overlay BEFORE mempool selection so any conflicting fee-bearing
    //     claim on the same box is excluded. Zero fee; proceeds to the
    //     miner P2PK.
    let max_block_cost = active_params.max_block_cost as u64;
    let max_block_size = active_params.max_block_size as u64;
    let phase_start = std::time::Instant::now();
    let rent_cost_ceiling = max_block_cost
        .saturating_sub(DEFAULT_COST_SAFETY_GAP)
        .saturating_sub(emission_cost)
        .saturating_sub(max_block_cost / 16);
    let rent_size_ceiling = max_block_size
        .saturating_sub(emission_size)
        .saturating_sub(max_block_size / 16);
    let (checked_rent, rent_cost, rent_size) = match build_budget_bounded_rent_claim(
        eligible_rent_boxes,
        candidate_height,
        &params,
        eligible_rent_boxes.len(),
        miner_pk,
        &ctx,
        last_headers.as_slice(),
        rent_cost_ceiling,
        rent_size_ceiling,
    )? {
        Some((checked, cost, size)) => {
            overlay.apply_tx(checked.transaction())?;
            (Some(checked), cost, size)
        }
        None => (None, 0, 0),
    };
    timings.rent_ms = phase_start.elapsed().as_millis() as u64;

    // 9d. Select mempool transactions into the budget remaining after the
    //     coinbase + rent claim. The overlay (emission + rent applied)
    //     excludes intra-block double-spends and rent conflicts; the budgets
    //     keep the block under the voted cost/size caps (candidate_dry_run
    //     checks neither).
    let phase_start = std::time::Instant::now();
    let cost_budget = max_block_cost
        .saturating_sub(DEFAULT_COST_SAFETY_GAP)
        .saturating_sub(emission_cost)
        .saturating_sub(rent_cost);
    let size_budget = max_block_size
        .saturating_sub(emission_size)
        .saturating_sub(rent_size)
        .saturating_sub(BLOCK_ASSEMBLY_SIZE_RESERVE);

    let selected = select_user_txs(
        &mut overlay,
        &mempool,
        &ctx,
        &params,
        last_headers.as_slice(),
        cost_budget,
        size_budget,
    )?;

    // 9e. Decide the final user set + fee tx. Trim the lowest-priority user
    //     tx (rebuilding the fee tx) until the assembled block fits BOTH the
    //     voted cost cap — emission + rent + user txs + the fee tx's OWN
    //     cost, under a safety gap — and the BlockTransactions size cap
    //     (rule 306). `candidate_dry_run` checks neither, and the fee tx's
    //     cost (one input per collected fee box) is otherwise unbudgeted, so
    //     a block could pass the dry-run yet be rejected at submit on
    //     `max_block_cost`. The fee tx is validated against a FRESH overlay
    //     rebuilt from the kept set, so a trimmed tx never leaves a stale
    //     spend behind.
    let mut user_checked = selected.checked; // Vec<(CheckedTransaction, cost)>
    let cost_ceiling = max_block_cost.saturating_sub(DEFAULT_COST_SAFETY_GAP);
    let checked_fee = loop {
        let user_raw: Vec<Transaction> = user_checked
            .iter()
            .map(|(c, _)| c.transaction().clone())
            .collect();
        let fee_tx_opt = build_fee_tx(&user_raw, miner_pk, candidate_height)?;

        // Fresh overlay over [emission, rent, kept user txs] so the fee tx's
        // inputs resolve against exactly the block's contents.
        let mut fee_overlay = CandidateOverlay::new(base);
        fee_overlay.apply_tx(&emission_tx)?;
        if let Some(cr) = &checked_rent {
            fee_overlay.apply_tx(cr.transaction())?;
        }
        for (c, _) in &user_checked {
            fee_overlay.apply_tx(c.transaction())?;
        }

        let (checked_fee, fee_cost) = match &fee_tx_opt {
            Some(fee_tx) => {
                let fee_bytes = serialize_tx(fee_tx, "serialize_fee_tx")?;
                let (fee_inputs, fee_data_inputs) =
                    fee_overlay
                        .resolve_tx(fee_tx)
                        .ok_or_else(|| MiningError::IdComputation {
                            op: "fee_tx_resolve",
                            reason: "fee-proposition box not resolvable against in-block overlay"
                                .into(),
                        })?;
                let mut fee_cost_acc = CostAccumulator::new(block_cap);
                let cf = {
                    let mut fee_ctx = TxValidationCtx {
                        ctx: &ctx,
                        params: &params,
                        cost: &mut fee_cost_acc,
                        last_headers: last_headers.as_slice(),
                    };
                    validate_transaction_parsed(
                        fee_tx.clone(),
                        &fee_bytes,
                        fee_inputs,
                        fee_data_inputs,
                        false,
                        &mut fee_ctx,
                    )
                    .map_err(|e| MiningError::IdComputation {
                        op: "validate_fee_tx",
                        reason: format!("{e:?}"),
                    })?
                };
                (Some(cf), fee_cost_acc.total_block_cost())
            }
            None => (None, 0),
        };

        let user_cost: u64 = user_checked.iter().map(|(_, cost)| *cost).sum();
        let total_cost = emission_cost
            .saturating_add(rent_cost)
            .saturating_add(user_cost)
            .saturating_add(fee_cost);

        let mut probe: Vec<Transaction> = Vec::with_capacity(3 + user_raw.len());
        probe.push(emission_tx.clone());
        if let Some(cr) = &checked_rent {
            probe.push(cr.transaction().clone());
        }
        probe.extend(user_raw);
        if let Some(ft) = &fee_tx_opt {
            probe.push(ft.clone());
        }
        let section_size = block_transactions_section_size(&probe, pre_header.version)?;

        if (total_cost <= cost_ceiling && section_size <= max_block_size as usize)
            || user_checked.is_empty()
        {
            break checked_fee;
        }
        user_checked.pop();
    };
    timings.select_ms = phase_start.elapsed().as_millis() as u64;

    // 9f. Assemble the final tx list in block order:
    //     emission, rent, user txs, fee.
    let mut checked: Vec<CheckedTransaction> = Vec::with_capacity(3 + user_checked.len());
    checked.push(checked_emission);
    if let Some(cr) = checked_rent {
        checked.push(cr);
    }
    for (c, _) in user_checked {
        checked.push(c);
    }
    if let Some(cf) = checked_fee {
        checked.push(cf);
    }
    let raw_txs: Vec<Transaction> = checked.iter().map(|c| c.transaction().clone()).collect();

    // 10. Dry-run AVL+ to obtain new_state_root + raw_proof_bytes.
    let phase_start = std::time::Instant::now();
    let (new_state_root, ad_proof_bytes, snapshot_tip_id) =
        view.candidate_dry_run(&checked).map_err(state_err)?;
    timings.dryrun_ms = phase_start.elapsed().as_millis() as u64;

    // 11. Parent-id guard: best-full advanced during generation.
    if snapshot_tip_id != parent_id {
        return Ok(None);
    }

    // 12. Compute roots.
    let phase_start = std::time::Instant::now();
    let ad_proofs_root = Digest32::from_bytes(*blake2b256(&ad_proof_bytes).as_bytes());

    let tx_ids_owned: Vec<[u8; 32]> = raw_txs
        .iter()
        .map(|tx| {
            let bts = bytes_to_sign(tx).map_err(|e| MiningError::IdComputation {
                op: "bytes_to_sign",
                reason: format!("{e:?}"),
            })?;
            Ok::<[u8; 32], MiningError>(*blake2b256(&bts).as_bytes())
        })
        .collect::<Result<_, _>>()?;
    let witness_ids_owned: Vec<Vec<u8>> = if pre_header.version >= 2 {
        raw_txs
            .iter()
            .map(|tx| {
                let mut all_proofs = Vec::new();
                for input in &tx.inputs {
                    all_proofs.extend_from_slice(&input.spending_proof.proof);
                }
                blake2b256(&all_proofs).as_bytes()[1..].to_vec()
            })
            .collect()
    } else {
        Vec::new()
    };

    let tx_id_slices: Vec<&[u8]> = tx_ids_owned.iter().map(|id| id.as_slice()).collect();
    let wit_slices: Vec<&[u8]> = witness_ids_owned.iter().map(|w| w.as_slice()).collect();
    let transactions_root_bytes = if pre_header.version >= 2 {
        transactions_root(&tx_id_slices, Some(&wit_slices))
    } else {
        transactions_root(&tx_id_slices, None)
    };

    let extension_field_refs: Vec<(&[u8], &[u8])> = extension_fields
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    let extension_root_bytes = extension_root(&extension_field_refs);
    timings.roots_ms = phase_start.elapsed().as_millis() as u64;

    // 13. Assemble header with placeholder solution.
    let placeholder_solution = AutolykosSolution::V2 {
        pk: ergo_primitives::group_element::GroupElement::from(*miner_pk),
        nonce: [0u8; 8],
    };
    let header = Header {
        version: pre_header.version,
        parent_id: Digest32::from_bytes(parent_id).into(),
        ad_proofs_root,
        transactions_root: Digest32::from_bytes(transactions_root_bytes),
        state_root: new_state_root,
        timestamp,
        extension_root: Digest32::from_bytes(extension_root_bytes),
        n_bits: new_n_bits,
        height: candidate_height,
        votes: [0u8; 3],
        unparsed_bytes: Vec::new(),
        solution: placeholder_solution,
    };

    // 14. Compute work message + target.
    let header_without_pow_bytes = serialize_header_without_pow(&header)?;
    let msg: [u8; 32] = *blake2b256(&header_without_pow_bytes).as_bytes();
    let target = get_target(new_n_bits);

    // 15. Build the typed work message (JSON marshalling happens at the
    //     node's mining bridge).
    let work_msg = WorkMessage {
        msg,
        target: target.clone(),
        height: candidate_height,
        pk: *miner_pk,
    };

    // 16. Pack the cached candidate.
    let candidate = Candidate {
        header,
        validation_ctx,
        transactions: raw_txs,
        ad_proof_bytes,
        extension_fields,
        msg,
        target,
        parent_id,
    };

    let _ = (validation_settings,); // reserved for v2 user-tx validation

    Ok(Some((candidate, work_msg, timings)))
}

// ---- private helpers ----

/// Headroom reserved under `max_block_size` when budgeting mempool
/// selection, leaving room for the fee tx + section framing. The exact
/// `block_transactions_section_size` guard trims the assembly if it still
/// overruns, so this only reduces how often that trim loop runs.
const BLOCK_ASSEMBLY_SIZE_RESERVE: u64 = 32_768;

fn serialize_tx(tx: &Transaction, op: &'static str) -> Result<Vec<u8>, MiningError> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, tx).map_err(|e| MiningError::IdComputation {
        op,
        reason: format!("{e:?}"),
    })?;
    Ok(w.result())
}

/// Serialized length of the `BlockTransactions` section (the rule-306
/// input). Mirrors `ergo-validation::check_block_transactions_size`, which
/// re-serializes via `write_block_transactions_with_version`. The header id
/// is a placeholder — only the byte length matters, and that is independent
/// of the 32-byte id's value.
fn block_transactions_section_size(
    txs: &[Transaction],
    block_version: u8,
) -> Result<usize, MiningError> {
    let bt = BlockTransactions {
        header_id: Digest32::from_bytes([0u8; 32]).into(),
        transactions: txs.to_vec(),
    };
    let mut w = VlqWriter::new();
    write_block_transactions_with_version(&mut w, &bt, block_version).map_err(|e| {
        MiningError::IdComputation {
            op: "block_transactions_size",
            reason: format!("{e:?}"),
        }
    })?;
    Ok(w.result().len())
}

fn state_err(e: ergo_state::store::StateError) -> MiningError {
    MiningError::StateRead {
        op: "candidate_assembly",
        reason: format!("{e:?}"),
    }
}

fn load_epoch_headers<V: CandidateStateView>(
    view: &V,
    needed: &[u32],
    parent_header: &Header,
) -> Result<Vec<Header>, MiningError> {
    let mut out = Vec::with_capacity(needed.len());
    for &h in needed {
        if h == 0 {
            // genesis pseudo-height: Scala's flatMap silently drops
            continue;
        }
        if h == parent_header.height {
            out.push(parent_header.clone());
            continue;
        }
        let id = view
            .header_id_at_height(h)
            .map_err(state_err)?
            .ok_or_else(|| MiningError::StateRead {
                op: "load_epoch_headers",
                reason: format!("no header at height {h}"),
            })?;
        let bytes = view
            .get_header_bytes(&id)
            .map_err(state_err)?
            .ok_or_else(|| MiningError::StateRead {
                op: "load_epoch_headers",
                reason: format!("header bytes missing for id {}", hex::encode(id)),
            })?;
        let mut r = VlqReader::new(&bytes);
        let hdr = read_header(&mut r).map_err(|e| MiningError::Decode {
            op: "epoch_header",
            reason: format!("h={h}: {e:?}"),
        })?;
        out.push(hdr);
    }
    Ok(out)
}

fn read_parent_extension_bytes<V: CandidateStateView>(
    view: &V,
    parent_header: &Header,
) -> Result<Vec<u8>, MiningError> {
    use ergo_ser::modifier_id::{compute_section_id, TYPE_EXTENSION};
    let parent_header_id: [u8; 32] = {
        // header_id is blake2b256 of full serialized header. We have the
        // parent in hand; re-serialize to compute.
        let (_, id) = ergo_ser::header::serialize_header(parent_header)?;
        *id.as_bytes()
    };
    let ext_section_id = compute_section_id(
        TYPE_EXTENSION,
        &parent_header_id,
        parent_header.extension_root.as_bytes(),
    );
    view.block_section(&ext_section_id)
        .map_err(state_err)?
        .ok_or_else(|| MiningError::StateRead {
            op: "load_parent_extension",
            reason: format!(
                "extension section {} not stored",
                hex::encode(ext_section_id)
            ),
        })
}

fn unpack_interlinks_from_extension(
    extension_bytes: &[u8],
) -> Result<Vec<ergo_primitives::digest::ModifierId>, MiningError> {
    // The parent's Extension section is stored in the canonical Scala wire
    // format — `[32-byte header_id][u16 n_fields]` then per field
    // `[2-byte key][u8 val_len][val]` — the exact shape `write_extension`
    // emits and block-apply / peer ingest persist. Decode it with the
    // canonical `read_extension` so the 2-byte keys (and thus the interlinks
    // fields) align with how blocks are actually written; a bespoke parser
    // would mis-frame every field.
    let mut r = VlqReader::new(extension_bytes);
    let ext = ergo_ser::extension::read_extension(&mut r).map_err(|e| MiningError::Decode {
        op: "parent_extension",
        reason: format!("{e:?}"),
    })?;
    // `unpack_interlinks` keeps only the interlinks-prefixed fields and ignores
    // any others (voted params, etc.).
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = ext
        .fields
        .into_iter()
        .map(|f| (f.key.to_vec(), f.value))
        .collect();
    unpack_interlinks(&pairs).map_err(|e| MiningError::Decode {
        op: "interlinks",
        reason: format!("{e:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::extension::{write_extension, Extension, ExtensionField};
    use ergo_validation::popow::algos::pack_interlinks;
    use serde::Deserialize;

    // ----- helpers -----

    /// Captured mainnet interlinks corpus entry (subset of fields needed
    /// here). Same JSON the `extension_builder` tests load.
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct InterlinksVector {
        height: u32,
        header_id: String,
        version: u8,
        n_interlinks_fields: usize,
        n_extension_fields_total: usize,
        interlinks_fields: Vec<[String; 2]>,
    }

    fn load_corpus(h: u32) -> InterlinksVector {
        let path = format!(
            "{}/../test-vectors/mining/interlinks_corpus/{}.json",
            env!("CARGO_MANIFEST_DIR"),
            h
        );
        serde_json::from_slice(&std::fs::read(&path).expect("read corpus")).expect("parse corpus")
    }

    /// Serialize an interlinks vector into the canonical Extension section
    /// bytes — `pack_interlinks` into 2-byte-keyed fields, then
    /// `write_extension` — i.e. exactly what `apply_mined_block` / peer ingest
    /// persist for a block's parent. This is the byte form the read side under
    /// test must accept.
    fn canonical_extension_bytes(header_id: [u8; 32], interlinks: &[ModifierId]) -> Vec<u8> {
        let fields = pack_interlinks(interlinks);
        let ext = Extension {
            header_id: ModifierId::from_bytes(header_id),
            fields: fields
                .into_iter()
                .map(|(k, v)| ExtensionField {
                    key: <[u8; 2]>::try_from(k.as_slice()).expect("interlinks key is 2 bytes"),
                    value: v,
                })
                .collect(),
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("write extension");
        w.result()
    }

    // ----- round-trips -----

    #[test]
    fn unpack_interlinks_from_canonically_written_extension_round_trips() {
        // The read side must consume exactly the bytes the canonical writer
        // emits (the format every applied block persists). Build an interlinks
        // vector with a duplicate run so `pack_interlinks`'s run-length
        // encoding is exercised, write it canonically, and assert the parser
        // recovers the original vector verbatim.
        let genesis = ModifierId::from_bytes([0x00u8; 32]);
        let a = ModifierId::from_bytes([0x11u8; 32]);
        let b = ModifierId::from_bytes([0x22u8; 32]);
        let interlinks = vec![genesis, a, a, a, b];

        let bytes = canonical_extension_bytes([0x9Au8; 32], &interlinks);
        let recovered =
            unpack_interlinks_from_extension(&bytes).expect("canonical extension parses");

        assert_eq!(
            recovered, interlinks,
            "the canonical writer's output must round-trip through the parser, \
             including the run-length-encoded duplicate run",
        );
    }

    #[test]
    fn unpack_interlinks_from_extension_without_interlinks_fields_is_empty() {
        // An extension carrying only non-interlinks 2-byte-key fields (e.g.
        // system-parameter `0x00..`) yields an empty interlinks vector without
        // error — `unpack_interlinks` ignores keys not prefixed with the
        // interlinks marker.
        let ext = Extension {
            header_id: ModifierId::from_bytes([0x7Cu8; 32]),
            fields: vec![
                ExtensionField {
                    key: [0x00, 0x01],
                    value: vec![0xDE, 0xAD],
                },
                ExtensionField {
                    key: [0x00, 0x02],
                    value: vec![0xBE, 0xEF],
                },
            ],
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("write extension");
        let bytes = w.result();

        let recovered = unpack_interlinks_from_extension(&bytes)
            .expect("non-interlinks extension parses without error");
        assert!(
            recovered.is_empty(),
            "an extension with no interlinks-prefixed fields yields no interlinks",
        );
    }

    #[test]
    fn unpack_interlinks_from_extension_with_mixed_fields_keeps_only_interlinks() {
        // A real parent extension interleaves interlinks fields with unrelated
        // ones (system parameters at epoch boundaries, miner-defined keys). The
        // parser must keep the interlinks-prefixed fields and ignore the rest,
        // recovering exactly the interlinks vector regardless of where the
        // foreign fields sit relative to the interlinks block.
        let genesis = ModifierId::from_bytes([0x00u8; 32]);
        let a = ModifierId::from_bytes([0x11u8; 32]);
        let b = ModifierId::from_bytes([0x22u8; 32]);
        let interlinks = vec![genesis, a, a, b];

        let mut fields = vec![ExtensionField {
            key: [0x00, 0x01],
            value: vec![0xDE, 0xAD],
        }];
        for (k, v) in pack_interlinks(&interlinks) {
            fields.push(ExtensionField {
                key: <[u8; 2]>::try_from(k.as_slice()).expect("interlinks key is 2 bytes"),
                value: v,
            });
        }
        fields.push(ExtensionField {
            key: [0x02, 0x00],
            value: vec![0xBE, 0xEF],
        });

        let ext = Extension {
            header_id: ModifierId::from_bytes([0x55u8; 32]),
            fields,
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("write extension");
        let bytes = w.result();

        let recovered = unpack_interlinks_from_extension(&bytes).expect("mixed extension parses");
        assert_eq!(
            recovered, interlinks,
            "the parser must keep only the interlinks-prefixed fields and ignore \
             unrelated extension fields, in any position",
        );
    }

    // ----- oracle parity -----

    #[test]
    fn unpack_interlinks_from_extension_recovers_real_mainnet_interlinks() {
        // Pin the section-byte parser against REAL captured mainnet interlinks:
        // block 100000 carries 7 interlinks fields with 2-byte keys
        // (0100/0101/0106/010e/010f/0111/0113) and 33-byte values. Build the
        // canonical Extension section from those captured fields, serialize it
        // exactly as an applied block persists, and assert the parser recovers
        // the same interlinks the established `unpack_interlinks` oracle does.
        // The old bespoke `[u8 key_len]` framing would mis-read the 2-byte keys
        // and fail here.
        let v = load_corpus(100_000);
        assert_eq!(v.n_interlinks_fields, v.interlinks_fields.len());

        let real_fields: Vec<(Vec<u8>, Vec<u8>)> = v
            .interlinks_fields
            .iter()
            .map(|p| {
                (
                    hex::decode(&p[0]).expect("hex key"),
                    hex::decode(&p[1]).expect("hex value"),
                )
            })
            .collect();

        let header_id_bytes: [u8; 32] = hex::decode(&v.header_id)
            .expect("hex header id")
            .try_into()
            .expect("header id is 32 bytes");

        let ext = Extension {
            header_id: ModifierId::from_bytes(header_id_bytes),
            fields: real_fields
                .iter()
                .map(|(k, val)| ExtensionField {
                    key: <[u8; 2]>::try_from(k.as_slice()).expect("interlinks key is 2 bytes"),
                    value: val.clone(),
                })
                .collect(),
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("write extension");
        let bytes = w.result();

        let recovered =
            unpack_interlinks_from_extension(&bytes).expect("real mainnet extension parses");
        assert!(
            !recovered.is_empty(),
            "a block with 7 captured interlinks fields yields a non-empty vector",
        );

        let oracle = unpack_interlinks(&real_fields).expect("oracle unpack");
        assert_eq!(
            recovered, oracle,
            "section-byte parser must recover the same interlinks the \
             unpack_interlinks oracle derives from the captured mainnet fields",
        );
    }
}
