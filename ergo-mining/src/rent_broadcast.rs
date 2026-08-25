//! Fee-paying broadcast storage-rent claim builder (Phase 1b).
//!
//! Unlike the privileged self-claim ([`crate::storage_rent_claim`], which a
//! node mining its own block pins for free), a node that wants its rent
//! claims mined by *other* miners must pay a competitive transaction fee.
//! This builder produces one of three shapes, all **ERG-conserving** and
//! **never burning tokens**:
//!
//! * **Batched** (≥2 claimable boxes) — a parent that recreates / consumes
//!   the boxes plus a fee output, a collector proceeds output, and a tiny
//!   `0008d3` anyone-can-spend **anchor** output; and a **CPFP child** (1
//!   input = the anchor, 1 output = the fee proposition) whose fee is sized
//!   by the unbeatable-child-fee formula so the parent+child family cannot
//!   be displaced by a single replacement bidding the entire extractable
//!   value `G` of the same boxes (`rent_fee_formula`).
//! * **Lone recreate** (1 recreate box) — parent only: recreate output +
//!   fee output (`parent_fee` = `max(min_relay_fee, parent_fee_per_input)`) +
//!   proceeds residual; no child.
//! * **Lone consumed** (1 full-consume box, `value ≤ fee`) — parent only:
//!   one minimal token box for the seized tokens + the residual value as
//!   the miner fee; no proceeds, no child.
//!
//! **Conservation is an identity, not a subtraction.** The collector
//! proceeds output is set to exactly the balancing residual so
//! `Σ inputs == Σ outputs` by construction; every other output's value is
//! already accounted for in that residual.
//!
//! **Never burn.** Each full-consume box keeps its tokens in its OWN
//! minimal box (≤122 tokens always fit one box). If a box's value can't
//! fund even that minimal box's dust, the box is SKIPPED (its tokens stay
//! on-chain) — never aggregated, never burned.
//!
//! Cost/size feeFactors are **measured** by validating the built txs (the
//! `build_budget_bounded_rent_claim` pattern), not analytical. The
//! challenger feeFactor is measured on the **leanest legal fee-bidding**
//! competitor (recreate outputs + one fee-proposition catch-all,
//! full-consume tokens burned) — a real adversary drops token outputs to
//! shrink and gain weight, but to have its bid `G` *recognized as fee* it
//! must put the residual on a fee-proposition output (the only shape the
//! mempool counts as fee), so that is the true leanest legal competitor. We
//! size against it; our own claim still never burns.

use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{read_ergo_tree, ErgoTree};
use ergo_ser::header::Header;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::{bytes_to_sign, write_transaction, Transaction};
use ergo_validation::storage_rent::compute_storage_fee;
use ergo_validation::{
    validate_transaction_parsed, CostAccumulator, ProtocolParams, ReemissionRuleInputs,
    TransactionContext, TxValidationCtx, TxValidationRules,
};

use crate::coinbase::MAINNET_FEE_PROPOSITION_BYTES;
use crate::error::MiningError;
use crate::rent_fee_formula::{unbeatable_child_fee, weight_value, FeeFactors};
use crate::storage_rent_claim::{
    box_min_value_and_size, build_p2pk_box, parse_p2pk_tree, rent_input,
};

/// Hard cap on the unbeatable-fee fixed-point loop. Each pass only changes
/// the VLQ encoding of a couple of amounts (child fee, anchor/proceeds
/// values) by a byte or two, so the measured feeFactors barely move and the
/// formula converges in ≤2 passes; the cap bounds a pathological flooring
/// oscillation. On non-convergence the batch is shrunk and the procedure
/// restarts (or the box-set is skipped).
const MAX_FEE_ITERS: usize = 3;

/// `00 08 d3` = `Const(SSigmaProp, TrivialProp::true)` — the 3-byte
/// anyone-can-spend anchor tree the CPFP child spends (and the lean
/// challenger's catch-all output). Pinned by
/// `storage_rent_claim::tests::anchor_tree_is_0008d3_and_round_trips`.
const ANCHOR_TREE_BYTES: [u8; 3] = [0x00, 0x08, 0xd3];

/// The shape a built claim took, for observability. Distinguishes the three
/// builder branches so the collector's broadcast log/metric can report which
/// family shape was relayed without re-deriving it from raw tx outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimShape {
    /// ≥2 boxes: a parent (recreate/consume + anchor + fee + proceeds) and a
    /// CPFP child.
    Batched,
    /// 1 recreate box: parent only (recreate + fee + proceeds), no child.
    LoneRecreate,
    /// 1 full-consume box (`value ≤ fee`): parent only (token box + fee),
    /// no proceeds, no child.
    LoneConsume,
}

impl ClaimShape {
    /// Stable, log-friendly label for the structured `info!`/metric field.
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimShape::Batched => "batched",
            ClaimShape::LoneRecreate => "lone-recreate",
            ClaimShape::LoneConsume => "lone-consume",
        }
    }
}

/// Observability summary of a built claim, populated by the builder at each
/// shape-construction site from the values already in scope. Purely additive:
/// the collector reads these for its structured broadcast log/metric instead
/// of fragilely re-deriving boxes/fees/proceeds from the serialized tx.
///
/// `parent_fee` is the parent's explicit fee-output value; `child_fee` is the
/// CPFP child's fee (`0` for the lone, child-less shapes); `proceeds` is the
/// collector's residual proceeds output (`0` for the lone-consume shape, which
/// has no proceeds output — the residual is the fee). `num_boxes` is the count
/// of rent boxes the parent claims.
#[derive(Debug, Clone, Copy)]
pub struct BroadcastSummary {
    /// Number of rent boxes claimed by the parent.
    pub num_boxes: usize,
    /// Which of the three shapes was built.
    pub shape: ClaimShape,
    /// The parent's explicit miner-fee output value.
    pub parent_fee: u64,
    /// The CPFP child's fee (`0` when there is no child).
    pub child_fee: u64,
    /// The collector's proceeds residual (`0` for the lone-consume shape).
    pub proceeds: u64,
}

/// A built fee-paying broadcast claim: the parent transaction plus its
/// resolved inputs (in tx-input order), and — for the batched shape — the
/// CPFP child and the parent's anchor output resolved as the child's input
/// box.
#[derive(Debug, Clone)]
pub struct BroadcastClaim {
    /// The parent rent-claim transaction (carries the fee output and, when
    /// batched, the anchor + proceeds outputs).
    pub parent: Transaction,
    /// The boxes the parent spends, in `parent.inputs` order.
    pub parent_inputs: Vec<ErgoBox>,
    /// The CPFP child (1-in anchor → 1-out fee proposition). `None` for the
    /// lone (parent-only) shapes.
    pub child: Option<Transaction>,
    /// The parent's anchor output, resolved as the child's input box (for
    /// child validation / admission). `None` when there is no child.
    pub child_input: Option<ErgoBox>,
    /// Observability summary (boxes/shape/fees/proceeds), populated at the
    /// shape-construction site. Additive — does not affect the family bytes.
    pub summary: BroadcastSummary,
}

/// Builder inputs populated at the call site (Phase 3) from
/// `[mining.rent_collector]` config + the live `MempoolConfig`: the relay
/// fee floor, the minimum net profit gate, and the mempool per-tx
/// admission caps the family must ALSO fit (not just consensus).
#[derive(Debug, Clone, Copy)]
pub struct FeeInputs {
    /// Relay fee floor — the lower bound of the parent fee (see `parent_fee`)
    /// and the floor the unbeatable child fee is clamped to.
    pub min_relay_fee: u64,
    /// Minimum net profit (config `min_profit_nanoerg`; default 0 = "claim
    /// anything affordable"). The proceeds residual must clear this.
    pub min_profit: u64,
    /// Mempool per-tx serialized-size admission cap.
    pub max_tx_size_bytes: u32,
    /// Mempool per-tx validation-cost admission cap.
    pub max_tx_cost: u64,
    /// Flat fee the recreate-bearing parent pays per input box claimed
    /// (config `parent_fee_per_input_nanoerg`). The parent fee is
    /// `max(min_relay_fee, parent_fee_per_input * num_input_boxes)` so the
    /// parent is mineable standalone (Ergo has no package relay; a CPFP child
    /// cannot lift a min-fee parent across the network). When batched, the
    /// unbeatable child fee auto-adjusts down as the parent carries more weight.
    pub parent_fee_per_input: u64,
}

impl FeeInputs {
    /// Parent transaction fee for a claim spending `num_inputs` rent boxes:
    /// `max(min_relay_fee, parent_fee_per_input * num_inputs)`. Saturating so
    /// an absurd configured per-input value can never overflow (it just pins to
    /// `u64::MAX`, which the downstream affordability gate then rejects).
    fn parent_fee(&self, num_inputs: usize) -> u64 {
        self.min_relay_fee
            .max(self.parent_fee_per_input.saturating_mul(num_inputs as u64))
    }
}

/// Deterministic ±bps offset for a node seed: ∈ `[-jitter_bps, +jitter_bps]`.
/// Returns `0` when jitter is inactive (`jitter_bps == 0` or `jitter_seed` is
/// `None`).
pub fn jitter_offset_bps(jitter_bps: u32, jitter_seed: Option<u64>) -> i64 {
    if jitter_bps == 0 {
        return 0;
    }
    let Some(seed) = jitter_seed else {
        return 0;
    };
    let span = (u64::from(jitter_bps).saturating_mul(2)).saturating_add(1);
    let h = stable_hash_u64(seed);
    (h % span) as i64 - i64::from(jitter_bps)
}

/// Apply deterministic per-node fee jitter to `base_fee_per_input`. Inactive
/// when `jitter_bps == 0` or `jitter_seed` is `None` → returns `base` unchanged.
/// Uses a `u128` intermediate so large bases cannot overflow.
pub fn jittered_parent_fee_per_input(
    base_fee_per_input: u64,
    jitter_bps: u32,
    jitter_seed: Option<u64>,
) -> u64 {
    if jitter_bps == 0 || jitter_seed.is_none() {
        return base_fee_per_input;
    }
    let offset = jitter_offset_bps(jitter_bps, jitter_seed);
    let factor = (10_000i64 + offset) as u128;
    let effective = (u128::from(base_fee_per_input).saturating_mul(factor)) / 10_000u128;
    (effective.min(u128::from(u64::MAX)) as u64).max(1)
}

/// Platform-independent splitmix64 over a seed — same seed → same hash on
/// every host/build (deterministic fleet jitter).
fn stable_hash_u64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Build a fee-paying broadcast rent claim for `eligible` boxes, or `None`
/// when nothing is profitably claimable.
///
/// Reuses the per-box gating from [`crate::storage_rent_claim`] verbatim
/// (too-young, fee-overflow, recreate dust / `max_box_size`) plus an
/// EIP-27 carve-out: any box carrying re-emission tokens is left unclaimed
/// (spending one requires burning the tokens and paying the
/// pay-to-reemission contract — incompatible with never-burn and with a
/// pure-burn challenger). When `reemission` is `None` (e.g. testnet) there
/// are no such tokens.
///
/// The returned family is guaranteed to (a) conserve ERG, (b) never burn
/// tokens, (c) pass `validate_transaction_parsed` at `current_height`, (d)
/// fit the mempool per-tx caps, and (e) for the batched shape, be
/// unbeatable on both the cost and size weight axes against the leanest
/// legal challenger bidding `G`.
#[allow(clippy::too_many_arguments)]
pub fn build_broadcast_claim(
    eligible: &[ErgoBox],
    current_height: u32,
    params: &ProtocolParams,
    primary_pubkey: &[u8; 33],
    ctx: &TransactionContext,
    last_headers: &[Header],
    reemission: Option<&ReemissionRuleInputs>,
    fee_inputs: &FeeInputs,
) -> Result<Option<BroadcastClaim>, MiningError> {
    // First pass: classify every eligible box into a claimable plan entry,
    // dropping anything the validator (or our never-burn policy) would
    // reject. Sorted highest-rent first so a shrink drops the lowest-rent
    // box (the least valuable to defend).
    let mut plan = classify(eligible, current_height, params, reemission)?;
    plan.sort_by_key(|e| std::cmp::Reverse(e.rent));

    // Shrink loop: try the whole set, and on non-convergence /
    // unaffordability drop the lowest-rent box and retry.
    while !plan.is_empty() {
        match try_build(
            &plan,
            current_height,
            params,
            primary_pubkey,
            ctx,
            last_headers,
            reemission,
            fee_inputs,
        )? {
            Some(claim) => return Ok(Some(claim)),
            None => {
                plan.pop(); // drop the lowest-rent box (sorted descending)
            }
        }
    }
    Ok(None)
}

/// A box classified as claimable, with its destination branch decided.
struct PlanEntry {
    /// The resolved box being claimed.
    box_: ErgoBox,
    /// Rent extracted from this box for `G` (recreate: `fee`; consume:
    /// `value`).
    rent: u64,
    /// Branch + per-box data.
    kind: PlanKind,
}

enum PlanKind {
    /// `value > fee`: recreate output preserving script/tokens/registers
    /// at the current height, value `value - fee`.
    Recreate { recreated_value: u64 },
    /// `value <= fee`: the whole box (value + tokens) is seized into its
    /// OWN minimal token box.
    Consume,
}

/// A built batched family: the parent tx + its resolved inputs, the CPFP
/// child tx, and the anchor output resolved as the child's input box.
type BatchedFamily = (Transaction, Vec<ErgoBox>, Transaction, ErgoBox);

/// Classify each eligible box, dropping anything unclaimable. Mirrors
/// `build_rent_claim`'s per-box gating exactly, plus the EIP-27 carve-out
/// and the never-burn per-box token-output check.
fn classify(
    eligible: &[ErgoBox],
    current_height: u32,
    params: &ProtocolParams,
    reemission: Option<&ReemissionRuleInputs>,
) -> Result<Vec<PlanEntry>, MiningError> {
    let max_box_size = params.max_box_size as usize;
    let mut plan = Vec::new();

    for b in eligible {
        // Too young (validator enforces box_age >= storage_period).
        let box_age = current_height.saturating_sub(b.candidate.creation_height);
        if box_age < params.storage_period {
            continue;
        }

        // EIP-27 carve-out: a box carrying re-emission tokens can't be
        // claimed without burning them + paying pay-to-reemission. Leave
        // it unclaimed.
        if carries_reemission_token(b, reemission) {
            continue;
        }

        // storageFee = storage_fee_factor *(i32 wrapping)* box_bytes_len;
        // a non-positive fee is consensus-uncollectable (overflow / factor
        // 0) — skip so the claim stays fork-free.
        let box_bytes_len = serialize_ergo_box(b)
            .map_err(|e| MiningError::IdComputation {
                op: "rent_box_serialize",
                reason: format!("{e:?}"),
            })?
            .len() as i32;
        let storage_fee = compute_storage_fee(box_bytes_len, params.storage_fee_factor);
        if storage_fee <= 0 {
            continue;
        }
        let fee = storage_fee as u64;

        if b.candidate.value > fee {
            // Recreate branch. The recreate output must clear dust and the
            // box-size cap, exactly as the self-claim gates it.
            let recreated_value = b.candidate.value - fee;
            let recreated = recreate_candidate(b, recreated_value, current_height);
            let (min_value, box_size) =
                box_min_value_and_size(&recreated, 0, params.min_value_per_byte)?;
            if recreated_value < min_value || box_size > max_box_size {
                continue;
            }
            plan.push(PlanEntry {
                box_: b.clone(),
                rent: fee,
                kind: PlanKind::Recreate { recreated_value },
            });
        } else {
            // Full-consume branch. Never-burn: the box gets its own minimal
            // token box. Skip if the token box would exceed max_box_size OR
            // the box value can't fund its dust (the tokens stay in place).
            let p2pk_tree = parse_p2pk_tree(&primary_pubkey_placeholder())?;
            let token_box = build_p2pk_box(
                b.candidate.value,
                &p2pk_tree,
                current_height,
                b.candidate.tokens.clone(),
            )?;
            // Dust is estimated at output index 0 (a 1-byte VLQ index). The
            // AUTHORITATIVE re-check runs in `build_batched_family` using the
            // real destination index. For output index >= 128 the VLQ index
            // is 2 bytes, so the real min_value can be 1 * min_value_per_byte
            // higher than estimated here — a barely-funded box that passes
            // this estimate may then fail the build-time re-check. That is a
            // SAFE over-shrink: the box is simply skipped (tokens stay on
            // chain), never burned, never breaking conservation, never
            // emitting an invalid tx. KNOWN FOLLOW-UP: tighten this estimate
            // to the real index (needs its own test to avoid over-skipping).
            let (min_value, box_size) =
                box_min_value_and_size(&token_box, 0, params.min_value_per_byte)?;
            if box_size > max_box_size || b.candidate.value < min_value {
                continue;
            }
            plan.push(PlanEntry {
                box_: b.clone(),
                rent: b.candidate.value,
                kind: PlanKind::Consume,
            });
        }
    }
    Ok(plan)
}

/// A placeholder pubkey used only for the classify-time dust check on a
/// consume box's token box. The token box's serialized SIZE is independent
/// of which 33-byte P2PK key locks it (all P2PK trees are the same length),
/// so the dust floor / size check is key-independent; the real key is
/// applied when the box is actually built in [`try_build`].
fn primary_pubkey_placeholder() -> [u8; 33] {
    // secp256k1 generator point, compressed — a valid P2PK key.
    [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ]
}

/// Build and validate a family for the given (already-classified,
/// rent-descending) plan. Returns `None` when the set is unaffordable or
/// the fee loop does not converge — the caller shrinks and retries.
#[allow(clippy::too_many_arguments)]
fn try_build(
    plan: &[PlanEntry],
    current_height: u32,
    params: &ProtocolParams,
    primary_pubkey: &[u8; 33],
    ctx: &TransactionContext,
    last_headers: &[Header],
    reemission: Option<&ReemissionRuleInputs>,
    fee_inputs: &FeeInputs,
) -> Result<Option<BroadcastClaim>, MiningError> {
    if plan.is_empty() {
        return Ok(None);
    }
    let batched = plan.len() >= 2;
    if batched {
        try_build_batched(
            plan,
            current_height,
            params,
            primary_pubkey,
            ctx,
            last_headers,
            reemission,
            fee_inputs,
        )
    } else {
        try_build_lone(
            &plan[0],
            current_height,
            params,
            primary_pubkey,
            ctx,
            last_headers,
            reemission,
            fee_inputs,
        )
    }
}

// ----- lone shapes (1 box, parent-only, no child) -----

#[allow(clippy::too_many_arguments)]
fn try_build_lone(
    entry: &PlanEntry,
    current_height: u32,
    params: &ProtocolParams,
    primary_pubkey: &[u8; 33],
    ctx: &TransactionContext,
    last_headers: &[Header],
    reemission: Option<&ReemissionRuleInputs>,
    fee_inputs: &FeeInputs,
) -> Result<Option<BroadcastClaim>, MiningError> {
    let max_box_size = params.max_box_size as usize;
    let p2pk_tree = parse_p2pk_tree(primary_pubkey)?;
    let fee_tree = parse_fee_tree()?;
    let input_value = entry.box_.candidate.value;

    match &entry.kind {
        PlanKind::Recreate { recreated_value } => {
            // Outputs: [recreate(0), fee(1), proceeds(2)].
            // parent_fee = the self-sufficient per-input fee (one input here).
            // proceeds = balancing residual = value - recreated_value - parent_fee.
            let parent_fee = fee_inputs.parent_fee(1);
            let recreated = recreate_candidate(&entry.box_, *recreated_value, current_height);
            let fee_box = build_fee_box(parent_fee, &fee_tree, current_height)?;

            let proceeds = match input_value
                .checked_sub(*recreated_value)
                .and_then(|v| v.checked_sub(parent_fee))
            {
                Some(p) => p,
                None => return Ok(None),
            };
            let proceeds_box = build_p2pk_box(proceeds, &p2pk_tree, current_height, Vec::new())?;
            let (proceeds_min, proceeds_size) =
                box_min_value_and_size(&proceeds_box, 2, params.min_value_per_byte)?;
            if proceeds < proceeds_min.max(fee_inputs.min_profit) || proceeds_size > max_box_size {
                return Ok(None);
            }

            let outputs = vec![recreated, fee_box, proceeds_box];
            let inputs = vec![rent_input(&entry.box_, 0)?];
            let parent = Transaction {
                inputs,
                data_inputs: Vec::new(),
                output_candidates: outputs,
            };
            let parent_inputs = vec![entry.box_.clone()];
            // Conservation + validation + mempool caps.
            assert_conserved(&parent, &parent_inputs);
            if !validate_and_fits(
                &parent,
                &parent_inputs,
                params,
                ctx,
                last_headers,
                reemission,
                fee_inputs,
            )? {
                return Ok(None);
            }
            Ok(Some(BroadcastClaim {
                parent,
                parent_inputs,
                child: None,
                child_input: None,
                summary: BroadcastSummary {
                    num_boxes: 1,
                    shape: ClaimShape::LoneRecreate,
                    parent_fee,
                    child_fee: 0,
                    proceeds,
                },
            }))
        }
        PlanKind::Consume => {
            // The full-consume residual IS the miner fee (no proceeds output
            // on this shape, no child). Ergo has no implicit fee — the fee is
            // an explicit fee-proposition output box. var-127 names the
            // output (any output is accepted on the full-consume branch).
            let has_tokens = !entry.box_.candidate.tokens.is_empty();

            let (outputs, parent_fee) = if !has_tokens {
                // No tokens to preserve → no token box. A single
                // fee-proposition output carries the FULL input value as the
                // miner fee. Require `input_value ≥ min_relay` (and the fee
                // box's own dust/size) or skip — no dust P2PK box left over.
                let fee_box = build_fee_box(input_value, &fee_tree, current_height)?;
                let (fee_min, fee_size) =
                    box_min_value_and_size(&fee_box, 0, params.min_value_per_byte)?;
                if input_value < fee_inputs.min_relay_fee
                    || input_value < fee_min
                    || fee_size > max_box_size
                {
                    return Ok(None);
                }
                (vec![fee_box], input_value)
            } else {
                // Outputs: [token_box(0), fee_box(1)]. The token box holds its
                // minimal dust (preserving the seized tokens); the fee box
                // (fee proposition) holds the residual `value − token_dust`.
                // Require the residual ≥ min_relay or skip.
                let token_box_full = build_p2pk_box(
                    input_value,
                    &p2pk_tree,
                    current_height,
                    entry.box_.candidate.tokens.clone(),
                )?;
                let (token_min, token_size) =
                    box_min_value_and_size(&token_box_full, 0, params.min_value_per_byte)?;
                if token_size > max_box_size {
                    return Ok(None);
                }
                // Give the token box exactly its dust; the rest is the fee box.
                let token_box = build_p2pk_box(
                    token_min,
                    &p2pk_tree,
                    current_height,
                    entry.box_.candidate.tokens.clone(),
                )?;
                let residual_fee = match input_value.checked_sub(token_min) {
                    Some(f) => f,
                    None => return Ok(None),
                };
                if residual_fee < fee_inputs.min_relay_fee {
                    return Ok(None);
                }
                let fee_box = build_fee_box(residual_fee, &fee_tree, current_height)?;
                let (fee_min, fee_size) =
                    box_min_value_and_size(&fee_box, 1, params.min_value_per_byte)?;
                if residual_fee < fee_min || fee_size > max_box_size {
                    return Ok(None);
                }
                (vec![token_box, fee_box], residual_fee)
            };

            let inputs = vec![rent_input(&entry.box_, 0)?];
            let parent = Transaction {
                inputs,
                data_inputs: Vec::new(),
                output_candidates: outputs,
            };
            let parent_inputs = vec![entry.box_.clone()];
            assert_conserved(&parent, &parent_inputs);
            if !validate_and_fits(
                &parent,
                &parent_inputs,
                params,
                ctx,
                last_headers,
                reemission,
                fee_inputs,
            )? {
                return Ok(None);
            }
            Ok(Some(BroadcastClaim {
                parent,
                parent_inputs,
                child: None,
                child_input: None,
                summary: BroadcastSummary {
                    // One rent box claimed in both lone-consume paths
                    // (no-token: single fee output; tokens: token box + fee).
                    num_boxes: 1,
                    shape: ClaimShape::LoneConsume,
                    parent_fee,
                    child_fee: 0,
                    proceeds: 0,
                },
            }))
        }
    }
}

// ----- batched shape (≥2 boxes, parent + CPFP child) -----

#[allow(clippy::too_many_arguments)]
fn try_build_batched(
    plan: &[PlanEntry],
    current_height: u32,
    params: &ProtocolParams,
    primary_pubkey: &[u8; 33],
    ctx: &TransactionContext,
    last_headers: &[Header],
    reemission: Option<&ReemissionRuleInputs>,
    fee_inputs: &FeeInputs,
) -> Result<Option<BroadcastClaim>, MiningError> {
    // Self-sufficient parent fee, scaled by the number of rent boxes claimed,
    // so the parent is mineable standalone. The unbeatable child fee below is
    // computed against THIS parent_fee and shrinks as the parent carries more
    // weight (see `unbeatable_child_fee`).
    let parent_fee = fee_inputs.parent_fee(plan.len());

    // G = max a challenger could bid = Σ recreate fees + Σ consume values.
    let mut g: u64 = 0;
    for e in plan {
        g = g.saturating_add(e.rent);
    }

    // Output layout (indices fixed before inputs so var-127 is correct):
    //   [recreate outputs..., consume token boxes..., anchor, fee, proceeds]
    // The anchor (child_fee), fee (parent_fee), and proceeds (residual)
    // come last; recreate/consume outputs come first so each input's
    // var-127 names a stable index.
    let p2pk_tree = parse_p2pk_tree(primary_pubkey)?;
    let fee_tree = parse_fee_tree()?;
    let anchor_tree = parse_anchor_tree()?;

    // Measure the lean challenger ONCE — it is independent of our child_fee.
    let challenger_cost;
    let challenger_size;
    {
        let (lc_tx, lc_inputs) = build_lean_challenger(plan, current_height, &fee_tree)?;
        let (c, s) = measure(&lc_tx, &lc_inputs, params, ctx, last_headers, reemission)?;
        challenger_cost = c;
        challenger_size = s;
    }

    // Fixed-point loop on child_fee. Start at min_relay_fee, measure, set
    // child_fee to the formula value, rebuild, re-measure; converge when the
    // formula no longer exceeds the fee we built with (then hard-guard
    // unbeatable on both axes before emitting).
    let mut child_fee = fee_inputs.min_relay_fee;
    for _ in 0..MAX_FEE_ITERS {
        let built = build_batched_family(
            plan,
            current_height,
            params,
            &p2pk_tree,
            &fee_tree,
            &anchor_tree,
            parent_fee,
            child_fee,
            fee_inputs,
        )?;
        let Some((parent, parent_inputs, child, child_input)) = built else {
            return Ok(None); // unaffordable / dust at this child_fee → shrink
        };

        // Measure our parent and child (challenger already measured).
        let (parent_cost, parent_size) = measure(
            &parent,
            &parent_inputs,
            params,
            ctx,
            last_headers,
            reemission,
        )?;
        let child_resolved = vec![child_input.clone()];
        let (child_cost, child_size) = measure(
            &child,
            &child_resolved,
            params,
            ctx,
            last_headers,
            reemission,
        )?;

        // Build & validate the measured FeeFactors (carry-forward #1: a 0
        // factor is a measurement bug, reported with context).
        let cost_ff = checked_fee_factors("cost", parent_cost, child_cost, challenger_cost)?;
        let size_ff = checked_fee_factors("size", parent_size, child_size, challenger_size)?;

        // The unbeatable child fee for this measurement.
        let formula_fee =
            unbeatable_child_fee(g, parent_fee, &cost_ff, &size_ff, fee_inputs.min_relay_fee)
                .map_err(|e| MiningError::IdComputation {
                    op: "unbeatable_child_fee",
                    reason: format!("{e:?}"),
                })?;
        // A saturated sentinel is unpayable — never broadcast it.
        if formula_fee == u64::MAX {
            return Ok(None);
        }

        // Converge directly on the formula value — it is already EXACT and
        // sufficient. `unbeatable_child_fee` returns the per-axis
        // `ceil(deficit_weight * FF_child / 1024)` (maxed, floored at
        // min_relay); the round-trip then gives
        // `weight(formula_fee) = floor(formula_fee * 1024 / FF_child) >=
        // deficit_weight`, so setting `child_fee = formula_fee` already makes
        // the family unbeatable on the MEASURED axes — no extra per-axis
        // flooring bump is needed (that bump only overpaid by a few nanoERG).
        // Bumping to `formula_fee` may shift the fee's VLQ length, hence the
        // re-measure on the next pass; at the fixed point `child_fee` equals
        // the formula recomputed against this very measurement.
        //
        // Converge on EQUALITY, not on `formula_fee > child_fee`: child_fee
        // starts at min_relay (<= formula, which is itself floored at
        // min_relay) and formula_fee is monotonic non-decreasing in child_fee
        // (larger fee -> larger child VLQ size -> larger size feeFactor ->
        // larger formula), so child_fee climbs and halts exactly at the fixed
        // point where `child_fee == formula_fee` — the exact minimum unbeatable
        // fee. Using `!=` (not `>`) makes it impossible to EMIT a fee greater
        // than the formula: if any measurement edge ever inverted monotonicity
        // (formula_fee < child_fee), we clamp DOWN to the formula and re-measure
        // rather than overpaying. Termination is bounded by MAX_FEE_ITERS;
        // non-convergence (e.g. a VLQ-boundary cross that doesn't settle within
        // the cap) falls through to the existing `Ok(None)` so the caller
        // shrinks/skips.
        if formula_fee != child_fee {
            child_fee = formula_fee;
            continue;
        }

        // Converged: `child_fee == formula_fee` (EXACT). The family is
        // unbeatable for its OWN measurement at exactly the formula minimum.
        // Guard the Critical properties.
        assert_conserved(&parent, &parent_inputs);

        // HARD fail-safe (load-bearing in RELEASE, not a debug_assert):
        // never emit a beatable family. If a lemma edge leaves the family
        // short on either axis, break to the caller's shrink-then-skip path
        // (the same fallthrough the MAX_FEE_ITERS non-convergence uses).
        if !(family_is_unbeatable(g, parent_fee, child_fee, &cost_ff)
            && family_is_unbeatable(g, parent_fee, child_fee, &size_ff))
        {
            break;
        }

        // Validate + fit mempool caps for both parent and child.
        if !validate_and_fits(
            &parent,
            &parent_inputs,
            params,
            ctx,
            last_headers,
            reemission,
            fee_inputs,
        )? {
            return Ok(None);
        }
        if !validate_and_fits(
            &child,
            &child_resolved,
            params,
            ctx,
            last_headers,
            reemission,
            fee_inputs,
        )? {
            return Ok(None);
        }

        // The proceeds output is the LAST parent output (anchor, fee, then
        // proceeds — see the fixed output layout in `build_batched_family`).
        let proceeds = parent
            .output_candidates
            .last()
            .map(|o| o.value)
            .unwrap_or(0);
        return Ok(Some(BroadcastClaim {
            parent,
            parent_inputs,
            child: Some(child),
            child_input: Some(child_input),
            summary: BroadcastSummary {
                num_boxes: plan.len(),
                shape: ClaimShape::Batched,
                parent_fee,
                child_fee,
                proceeds,
            },
        }));
    }

    // Did not converge within the cap → caller shrinks the batch.
    Ok(None)
}

/// Assemble the batched parent + child for a given `child_fee`. Returns
/// `None` (skip / shrink) when the box-set is unaffordable or any output
/// fails its dust / box-size gate at this fee.
#[allow(clippy::too_many_arguments)]
fn build_batched_family(
    plan: &[PlanEntry],
    current_height: u32,
    params: &ProtocolParams,
    p2pk_tree: &ErgoTree,
    fee_tree: &ErgoTree,
    anchor_tree: &ErgoTree,
    parent_fee: u64,
    child_fee: u64,
    fee_inputs: &FeeInputs,
) -> Result<Option<BatchedFamily>, MiningError> {
    let max_box_size = params.max_box_size as usize;

    let mut outputs: Vec<ErgoBoxCandidate> = Vec::new();
    // var-127 destination index per plan entry, in plan order.
    let mut dest_index: Vec<usize> = Vec::with_capacity(plan.len());

    // Recreate + consume outputs first.
    for e in plan {
        let idx = outputs.len();
        match &e.kind {
            PlanKind::Recreate { recreated_value } => {
                let recreated = recreate_candidate(&e.box_, *recreated_value, current_height);
                let (min_value, box_size) =
                    box_min_value_and_size(&recreated, idx, params.min_value_per_byte)?;
                if *recreated_value < min_value || box_size > max_box_size {
                    return Ok(None);
                }
                outputs.push(recreated);
            }
            PlanKind::Consume => {
                // The token box holds only its minimal dust; the seized
                // `value − dust` joins the proceeds pool (via the
                // conservation identity below). Never burn: every token
                // stays in this box.
                let probe = build_p2pk_box(
                    e.box_.candidate.value,
                    p2pk_tree,
                    current_height,
                    e.box_.candidate.tokens.clone(),
                )?;
                let (min_value, box_size) =
                    box_min_value_and_size(&probe, idx, params.min_value_per_byte)?;
                if e.box_.candidate.value < min_value || box_size > max_box_size {
                    return Ok(None);
                }
                let token_box = build_p2pk_box(
                    min_value,
                    p2pk_tree,
                    current_height,
                    e.box_.candidate.tokens.clone(),
                )?;
                outputs.push(token_box);
            }
        }
        dest_index.push(idx);
    }

    // Anchor (value = child_fee), fee (value = parent_fee), proceeds (residual).
    //
    // ANCHOR-LEAK TRADEOFF: the anchor is an anyone-can-spend box (`anchor_tree`)
    // holding `child_fee`; the CPFP child spends it into the miner-fee box. Now
    // that the parent carries a self-sufficient fee (`parent_fee` scaled per
    // input), a fee-sorting miner can mine the PARENT ALONE — and a rational one
    // that also holds the child includes it too (the child is high fee/byte), so
    // the anchor is consumed in the same block and nothing leaks. The anchor
    // only persists as a public anyone-can-spend UTXO if a miner takes the
    // parent WITHOUT the child (child did not co-propagate). That value is
    // conserved (already debited from proceeds, never burned) and reclaimable by
    // anyone, but it is not collected by us in that case. Kept deliberately:
    // the operator chose "leave the [unbeatable] formula as is" — the child
    // still makes the family unbeatable for family-weight-aware miners. A
    // follow-up could drop the child when the parent alone is already unbeatable
    // (deficit == 0) to remove the anchor entirely; see the design doc.
    let anchor_idx = outputs.len();
    let anchor_box = build_value_box(child_fee, anchor_tree, current_height)?;
    let (anchor_min, anchor_size) =
        box_min_value_and_size(&anchor_box, anchor_idx, params.min_value_per_byte)?;
    if child_fee < anchor_min || anchor_size > max_box_size {
        return Ok(None);
    }
    outputs.push(anchor_box);

    let fee_idx = outputs.len();
    let fee_box = build_fee_box(parent_fee, fee_tree, current_height)?;
    let (fee_min, fee_size) = box_min_value_and_size(&fee_box, fee_idx, params.min_value_per_byte)?;
    if parent_fee < fee_min || fee_size > max_box_size {
        return Ok(None);
    }
    outputs.push(fee_box);

    // proceeds = Σ inputs − Σ recreate outputs − Σ consume token boxes −
    //            parent_fee − child_fee, computed with checked arithmetic.
    let total_in: u64 = plan
        .iter()
        .try_fold(0u64, |acc, e| acc.checked_add(e.box_.candidate.value))
        .ok_or_else(|| MiningError::IdComputation {
            op: "broadcast_total_in",
            reason: "input value sum overflow".to_string(),
        })?;
    // Σ of every non-proceeds output value already in `outputs`.
    let mut spent: u64 = 0;
    for o in &outputs {
        spent = match spent.checked_add(o.value) {
            Some(v) => v,
            None => return Ok(None),
        };
    }
    let proceeds = match total_in.checked_sub(spent) {
        Some(p) => p,
        None => return Ok(None), // residual underflow → unaffordable
    };

    let proceeds_idx = outputs.len();
    let proceeds_box = build_p2pk_box(proceeds, p2pk_tree, current_height, Vec::new())?;
    let (proceeds_min, proceeds_size) =
        box_min_value_and_size(&proceeds_box, proceeds_idx, params.min_value_per_byte)?;
    if proceeds < proceeds_min.max(fee_inputs.min_profit) || proceeds_size > max_box_size {
        return Ok(None);
    }
    outputs.push(proceeds_box);

    // Inputs in plan order, each var-127 naming its destination index.
    let mut inputs: Vec<Input> = Vec::with_capacity(plan.len());
    let mut parent_inputs: Vec<ErgoBox> = Vec::with_capacity(plan.len());
    for (e, &idx) in plan.iter().zip(&dest_index) {
        inputs.push(rent_input(&e.box_, idx)?);
        parent_inputs.push(e.box_.clone());
    }

    let parent = Transaction {
        inputs,
        data_inputs: Vec::new(),
        output_candidates: outputs,
    };

    // The CPFP child: 1-in (the parent's anchor output) → 1-out (fee
    // proposition, value = child_fee). The whole anchor value becomes fee.
    let parent_tx_id = transaction_id(&parent)?;
    let anchor_candidate = parent.output_candidates[anchor_idx].clone();
    // Bound the narrowing rather than silently wrapping (mirrors
    // `rent_input`'s i16 bound). Unreachable in practice — a parent with
    // anchor_idx > u16::MAX would need >65535 preceding outputs, each of
    // which already trips `rent_input`'s i16 cap — but make the invariant
    // explicit.
    let child_index = u16::try_from(anchor_idx).map_err(|_| MiningError::IdComputation {
        op: "broadcast_anchor_index",
        reason: format!("anchor output index {anchor_idx} exceeds u16::MAX"),
    })?;
    let child_input = ErgoBox {
        candidate: anchor_candidate,
        transaction_id: parent_tx_id,
        index: child_index,
    };
    let child_fee_box = build_fee_box(child_fee, fee_tree, current_height)?;
    let child = Transaction {
        inputs: vec![anchor_spend_input(&child_input)?],
        data_inputs: Vec::new(),
        output_candidates: vec![child_fee_box],
    };

    Ok(Some((parent, parent_inputs, child, child_input)))
}

/// Build the LEAN CHALLENGER template (measurement only): the leanest legal
/// **fee-bidding** tx a competitor could make for the SAME boxes — required
/// recreate outputs (preserving each `value > fee` box) + ONE catch-all
/// **fee-proposition** output for every full-consume box's var-127, with
/// full-consume **tokens burned** (no token outputs, no proceeds, no
/// anchor). Token burning is consensus-legal and the full-consume branch
/// accepts any output, so a real adversary uses exactly this shape to shrink
/// and gain weight. We size against it; our own claim never burns.
fn build_lean_challenger(
    plan: &[PlanEntry],
    current_height: u32,
    fee_tree: &ErgoTree,
) -> Result<(Transaction, Vec<ErgoBox>), MiningError> {
    let mut outputs: Vec<ErgoBoxCandidate> = Vec::new();
    let mut dest_index: Vec<usize> = Vec::with_capacity(plan.len());
    let mut consume_present = false;

    // Recreate outputs (each box's var-127 names its own output).
    for e in plan {
        match &e.kind {
            PlanKind::Recreate { recreated_value } => {
                let idx = outputs.len();
                outputs.push(recreate_candidate(
                    &e.box_,
                    *recreated_value,
                    current_height,
                ));
                dest_index.push(idx);
            }
            PlanKind::Consume => {
                consume_present = true;
                dest_index.push(usize::MAX); // patched to catch-all below
            }
        }
    }

    // ONE catch-all output. Full-consume var-127s point here; tokens are
    // BURNED (the catch-all carries none). It also sinks the residual ERG
    // so the template is ERG-conserving and validatable for measurement.
    //
    // The catch-all MUST be a **fee-proposition** box, not P2PK: a real
    // challenger that wants its bid `G` recognized as fee has to put `G` on
    // a fee-proposition output (the mempool counts ONLY fee-proposition
    // outputs as fee — see `ergo-mempool::validator`). The fee proposition
    // is larger than P2PK, so a P2PK catch-all would under-measure the
    // challenger's size, over-estimate its weight, and inflate the child fee
    // we must pay. Using the same fee-proposition tree as our own fee output
    // makes this the exact leanest legal fee-bidding competitor. Its value
    // is the balancing residual (the template's exact fee value doesn't
    // affect its measured cost/size, only its structure does).
    let catch_all_idx = outputs.len();
    let total_in: u64 = plan
        .iter()
        .try_fold(0u64, |acc, e| acc.checked_add(e.box_.candidate.value))
        .ok_or_else(|| MiningError::IdComputation {
            op: "challenger_total_in",
            reason: "input value sum overflow".to_string(),
        })?;
    // Saturating (not bare `.sum()`) to match `total_in`'s checked style;
    // it only feeds `total_in.saturating_sub(...)` below, so an overflowed
    // sum still yields a sane (zero) catch-all value for this measurement
    // template — it never breaks conservation or is broadcast.
    let recreate_sum: u64 = outputs
        .iter()
        .fold(0u64, |acc, o| acc.saturating_add(o.value));
    let catch_all_value = total_in.saturating_sub(recreate_sum);
    let catch_all = build_fee_box(catch_all_value, fee_tree, current_height)?;
    outputs.push(catch_all);

    // Patch consume entries to the catch-all index.
    if consume_present {
        for d in dest_index.iter_mut() {
            if *d == usize::MAX {
                *d = catch_all_idx;
            }
        }
    }

    let mut inputs: Vec<Input> = Vec::with_capacity(plan.len());
    let mut resolved: Vec<ErgoBox> = Vec::with_capacity(plan.len());
    for (e, &idx) in plan.iter().zip(&dest_index) {
        inputs.push(rent_input(&e.box_, idx)?);
        resolved.push(e.box_.clone());
    }
    Ok((
        Transaction {
            inputs,
            data_inputs: Vec::new(),
            output_candidates: outputs,
        },
        resolved,
    ))
}

// ----- measurement + validation -----

/// Validate `tx` against `resolved_inputs` (at `ctx.height`) with a
/// recording-only cost accumulator and return `(block_cost, serialized
/// size)`. Errors out (rather than `Ok(None)`) on validation failure: a
/// builder-produced tx that does not validate is a bug to surface, not a
/// recoverable input.
fn measure(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
    params: &ProtocolParams,
    ctx: &TransactionContext,
    last_headers: &[Header],
    reemission: Option<&ReemissionRuleInputs>,
) -> Result<(u64, u64), MiningError> {
    let bytes = serialize_tx(tx)?;
    let size = bytes.len() as u64;
    let mut cost_acc = CostAccumulator::recording_only();
    {
        let mut cx = TxValidationCtx {
            ctx,
            params,
            cost: &mut cost_acc,
            last_headers,
            rules: TxValidationRules { reemission },
        };
        validate_transaction_parsed(
            tx.clone(),
            &bytes,
            resolved_inputs.to_vec(),
            Vec::new(),
            false,
            &mut cx,
        )
        .map_err(|e| MiningError::IdComputation {
            op: "measure_broadcast_tx",
            reason: format!("{e:?}"),
        })?;
    }
    Ok((cost_acc.total_block_cost(), size))
}

/// Validate `tx` and confirm it fits the mempool per-tx admission caps.
/// Returns `Ok(false)` when the tx exceeds a cap (caller shrinks); errors
/// only on an actual validation failure (a builder bug).
#[allow(clippy::too_many_arguments)]
fn validate_and_fits(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
    params: &ProtocolParams,
    ctx: &TransactionContext,
    last_headers: &[Header],
    reemission: Option<&ReemissionRuleInputs>,
    fee_inputs: &FeeInputs,
) -> Result<bool, MiningError> {
    let (cost, size) = measure(tx, resolved_inputs, params, ctx, last_headers, reemission)?;
    Ok(size <= fee_inputs.max_tx_size_bytes as u64 && cost <= fee_inputs.max_tx_cost)
}

/// Build `FeeFactors` from measured cost/size, validating each is `> 0`
/// (carry-forward #1: a 0 measured factor is a builder/measurement failure,
/// surfaced with context rather than fed to the spec-literal formula).
fn checked_fee_factors(
    axis: &'static str,
    parent: u64,
    child: u64,
    challenger: u64,
) -> Result<FeeFactors, MiningError> {
    for (role, v) in [
        ("parent", parent),
        ("child", child),
        ("challenger", challenger),
    ] {
        if v == 0 {
            return Err(MiningError::IdComputation {
                op: "broadcast_fee_factor",
                reason: format!("measured {axis} {role} feeFactor is 0 (measurement bug)"),
            });
        }
    }
    Ok(FeeFactors {
        parent,
        child,
        challenger,
    })
}

// ----- unbeatable helpers -----
//
// These ask a different question than `rent_fee_formula::unbeatable_child_fee`
// (does THIS already-built family clear the challenger?), so they live here.
// They share the SINGLE weight definition via `rent_fee_formula::weight_value`
// so the unbeatable assert can never drift from the formula's own weight math.

/// `true` iff `weight(parent) + weight(child) >= weight(G)` on this axis.
fn family_is_unbeatable(g: u64, parent_fee: u64, child_fee: u64, ff: &FeeFactors) -> bool {
    let family = weight_value(parent_fee, ff.parent) + weight_value(child_fee, ff.child);
    family >= weight_value(g, ff.challenger)
}

// ----- box / tree builders -----

/// The recreate output: preserves script/tokens/registers verbatim at the
/// current height with value `recreated_value` (mirrors the self-claim).
fn recreate_candidate(b: &ErgoBox, recreated_value: u64, current_height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::from_trusted_raw_parts(
        recreated_value,
        b.candidate.ergo_tree().clone(),
        b.candidate.ergo_tree_bytes().to_vec(),
        current_height,
        b.candidate.tokens.clone(),
        b.candidate.additional_registers.clone(),
        b.candidate.register_bytes().to_vec(),
    )
}

/// A value-only box (no tokens, no registers) locked by `tree`.
fn build_value_box(
    value: u64,
    tree: &ErgoTree,
    height: u32,
) -> Result<ErgoBoxCandidate, MiningError> {
    ErgoBoxCandidate::new(
        value,
        tree.clone(),
        height,
        Vec::new(),
        AdditionalRegisters::empty(),
    )
    .map_err(|e| MiningError::IdComputation {
        op: "broadcast_value_box",
        reason: format!("{e:?}"),
    })
}

/// The miner-fee output (fee proposition, no tokens).
fn build_fee_box(
    value: u64,
    fee_tree: &ErgoTree,
    height: u32,
) -> Result<ErgoBoxCandidate, MiningError> {
    build_value_box(value, fee_tree, height)
}

/// Parse the shared mainnet fee-proposition tree (the parent/child fee
/// output lock).
fn parse_fee_tree() -> Result<ErgoTree, MiningError> {
    let mut r = VlqReader::new(MAINNET_FEE_PROPOSITION_BYTES);
    read_ergo_tree(&mut r).map_err(|e| MiningError::Decode {
        op: "broadcast_fee_tree",
        reason: format!("{e:?}"),
    })
}

/// Parse the `0008d3` anyone-can-spend anchor tree.
fn parse_anchor_tree() -> Result<ErgoTree, MiningError> {
    let mut r = VlqReader::new(&ANCHOR_TREE_BYTES);
    read_ergo_tree(&mut r).map_err(|e| MiningError::Decode {
        op: "broadcast_anchor_tree",
        reason: format!("{e:?}"),
    })
}

/// The child's input spending the anchor box: empty proof (the `0008d3`
/// guard is trivially true), empty extension.
fn anchor_spend_input(child_input: &ErgoBox) -> Result<Input, MiningError> {
    let box_id = child_input
        .box_id()
        .map_err(|e| MiningError::IdComputation {
            op: "anchor_box_id",
            reason: format!("{e:?}"),
        })?;
    Ok(Input {
        box_id,
        spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).map_err(|e| {
            MiningError::IdComputation {
                op: "anchor_spending_proof",
                reason: format!("{e:?}"),
            }
        })?,
    })
}

// ----- misc helpers -----

/// Does `b` carry the EIP-27 re-emission token? `false` when no reemission
/// rules are active (e.g. testnet).
fn carries_reemission_token(b: &ErgoBox, reemission: Option<&ReemissionRuleInputs>) -> bool {
    let Some(rules) = reemission else {
        return false;
    };
    b.candidate
        .tokens
        .iter()
        .any(|t| t.token_id.as_bytes() == &rules.reemission_token_id)
}

/// Serialize a transaction to its wire bytes.
fn serialize_tx(tx: &Transaction) -> Result<Vec<u8>, MiningError> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, tx).map_err(|e| MiningError::IdComputation {
        op: "serialize_broadcast_tx",
        reason: format!("{e:?}"),
    })?;
    Ok(w.result())
}

/// `tx_id = Blake2b256(bytes_to_sign(tx))`.
fn transaction_id(tx: &Transaction) -> Result<ModifierId, MiningError> {
    let bts = bytes_to_sign(tx).map_err(|e| MiningError::IdComputation {
        op: "broadcast_bytes_to_sign",
        reason: format!("{e:?}"),
    })?;
    Ok(ModifierId::from_bytes(*blake2b256(&bts).as_bytes()))
}

/// Debug-assert `Σ input values == Σ output values` for the explicit-fee
/// shapes (batched, lone-recreate, lone-consume), where the fee is a
/// designated output box so the sum identity holds exactly. The Critical
/// correctness property.
fn assert_conserved(tx: &Transaction, resolved_inputs: &[ErgoBox]) {
    let in_sum: u64 = resolved_inputs.iter().map(|b| b.candidate.value).sum();
    let out_sum: u64 = tx.output_candidates.iter().map(|o| o.value).sum();
    debug_assert_eq!(
        in_sum, out_sum,
        "ERG conservation broken: Σ inputs ({in_sum}) != Σ outputs ({out_sum})"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_ser::token::Token;

    // ----- fee jitter -----

    #[test]
    fn jitter_offset_bps_inactive_when_bps_zero_or_seed_none() {
        assert_eq!(jitter_offset_bps(0, Some(42)), 0);
        assert_eq!(jitter_offset_bps(300, None), 0);
        assert_eq!(jitter_offset_bps(0, None), 0);
    }

    #[test]
    fn jitter_offset_bps_deterministic_and_in_range() {
        let j = 300u32;
        let a = jitter_offset_bps(j, Some(7));
        let b = jitter_offset_bps(j, Some(7));
        assert_eq!(a, b);
        assert!((-i64::from(j)..=i64::from(j)).contains(&a));
        // Distinct seeds usually differ (not a hard guarantee for all pairs,
        // but these two are known-distinct under splitmix).
        let c = jitter_offset_bps(j, Some(8));
        assert_ne!(a, c);
    }

    #[test]
    fn jittered_parent_fee_inactive_returns_base_unchanged() {
        assert_eq!(
            jittered_parent_fee_per_input(10_000_000, 0, Some(1)),
            10_000_000
        );
        assert_eq!(
            jittered_parent_fee_per_input(10_000_000, 300, None),
            10_000_000
        );
        assert_eq!(jittered_parent_fee_per_input(0, 0, None), 0);
    }

    #[test]
    fn jittered_parent_fee_scales_within_bps_and_no_u64_overflow() {
        let base = 10_000_000u64;
        let j = 300u32;
        let eff = jittered_parent_fee_per_input(base, j, Some(99));
        let lo = base * (10_000 - j as u64) / 10_000;
        let hi = base * (10_000 + j as u64) / 10_000;
        assert!((lo..=hi).contains(&eff), "eff={eff} not in [{lo},{hi}]");

        // Large base must not overflow the intermediate (u128 path).
        let huge = u64::MAX / 2;
        let huge_eff = jittered_parent_fee_per_input(huge, j, Some(1));
        assert!(huge_eff > 0);
    }

    // secp256k1 generator point, compressed — a valid P2PK pubkey.
    const PK: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];

    fn trivial_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    fn box_with_tokens(value: u64, creation_height: u32, seed: u8, tokens: Vec<Token>) -> ErgoBox {
        let cand = ErgoBoxCandidate::new(
            value,
            trivial_tree(),
            creation_height,
            tokens,
            AdditionalRegisters::empty(),
        )
        .unwrap();
        ErgoBox {
            candidate: cand,
            transaction_id: ModifierId::from_bytes([seed; 32]),
            index: 0,
        }
    }

    fn aged_box(value: u64, creation_height: u32, seed: u8) -> ErgoBox {
        box_with_tokens(value, creation_height, seed, vec![])
    }

    fn tokens_from(start: u8, n: u8) -> Vec<Token> {
        (0..n)
            .map(|i| Token {
                token_id: Digest32::from_bytes([start.wrapping_add(i); 32]),
                amount: 1,
            })
            .collect()
    }

    fn rent_params(storage_period: u32, storage_fee_factor: i32) -> ProtocolParams {
        let mut p = ProtocolParams::mainnet_default();
        p.storage_period = storage_period;
        p.storage_fee_factor = storage_fee_factor;
        p
    }

    fn ctx_at(height: u32) -> TransactionContext {
        TransactionContext {
            height,
            miner_pubkey: PK,
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        }
    }

    /// Default fee inputs: 1M relay floor, no profit gate, generous caps.
    /// `parent_fee_per_input = 0` so `parent_fee()` collapses to the relay
    /// floor — the pre-self-sufficient-parent baseline the bulk of these tests
    /// assert against. Tests exercising the per-input parent fee build their
    /// own `FeeInputs` with a non-zero value.
    fn fee_inputs() -> FeeInputs {
        FeeInputs {
            min_relay_fee: 1_000_000,
            min_profit: 0,
            max_tx_size_bytes: u32::MAX,
            max_tx_cost: u64::MAX,
            parent_fee_per_input: 0,
        }
    }

    fn build(
        eligible: &[ErgoBox],
        height: u32,
        params: &ProtocolParams,
        fee_inputs: &FeeInputs,
    ) -> Option<BroadcastClaim> {
        build_broadcast_claim(
            eligible,
            height,
            params,
            &PK,
            &ctx_at(height),
            &[],
            None,
            fee_inputs,
        )
        .expect("builder must not error")
    }

    fn sum_in(claim_inputs: &[ErgoBox]) -> u64 {
        claim_inputs.iter().map(|b| b.candidate.value).sum()
    }
    fn sum_out(tx: &Transaction) -> u64 {
        tx.output_candidates.iter().map(|o| o.value).sum()
    }

    /// Resolve + validate a tx through the real consensus validator.
    fn validate(tx: &Transaction, resolved: &[ErgoBox], height: u32, params: &ProtocolParams) {
        let bytes = serialize_tx(tx).unwrap();
        let mut cost = CostAccumulator::new(
            ergo_validation::JitCost::from_block_cost(params.max_block_cost).unwrap(),
        );
        let ctx = ctx_at(height);
        let mut cx = TxValidationCtx {
            ctx: &ctx,
            params,
            cost: &mut cost,
            last_headers: &[],
            rules: TxValidationRules::default(),
        };
        validate_transaction_parsed(
            tx.clone(),
            &bytes,
            resolved.to_vec(),
            Vec::new(),
            false,
            &mut cx,
        )
        .expect("tx must pass consensus validation");
    }

    // ===== batched =====

    #[test]
    fn batched_family_parent_has_proceeds_fee_anchor_outputs_and_child() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes = vec![
            aged_box(10_000_000_000, 0, 0x01),
            aged_box(10_000_000_000, 0, 0x02),
            aged_box(10_000_000_000, 0, 0x03),
        ];
        let claim = build(&boxes, height, &params, &fee_inputs()).expect("batched claim");
        assert!(claim.child.is_some(), "batched ⇒ has a CPFP child");
        assert!(claim.child_input.is_some(), "batched ⇒ has a child input");
        // Outputs: 3 recreate + anchor + fee + proceeds = 6.
        assert_eq!(claim.parent.output_candidates.len(), 6);
        // The anchor output value equals the child's input value equals the
        // child's single output (fee) value.
        let child = claim.child.as_ref().unwrap();
        assert_eq!(child.inputs.len(), 1);
        assert_eq!(child.output_candidates.len(), 1);
        let anchor_value = claim.child_input.as_ref().unwrap().candidate.value;
        assert_eq!(child.output_candidates[0].value, anchor_value);
    }

    #[test]
    fn parent_erg_is_exactly_conserved() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes = vec![
            aged_box(10_000_000_000, 0, 0x11),
            aged_box(8_000_000_000, 0, 0x12),
            aged_box(6_000_000_000, 0, 0x13),
        ];
        let claim = build(&boxes, height, &params, &fee_inputs()).expect("claim");
        assert_eq!(
            sum_in(&claim.parent_inputs),
            sum_out(&claim.parent),
            "parent Σ inputs must equal Σ outputs (the Critical identity)"
        );
        // Child conserves too (anchor value == fee output value).
        let child = claim.child.unwrap();
        let child_in = claim.child_input.unwrap().candidate.value;
        assert_eq!(child_in, sum_out(&child));
    }

    #[test]
    fn child_fee_equals_unbeatable_formula() {
        // Re-derive the unbeatable fee from the FINAL MEASURED feeFactors and
        // confirm the built child fee (anchor value) is EXACTLY it: the loop
        // converges on the formula value, never overpaying, and the family is
        // still unbeatable on both axes at that exact fee.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes: Vec<ErgoBox> = (0u8..4)
            .map(|i| aged_box(10_000_000_000, 0, 0x21 + i))
            .collect();
        let claim = build(&boxes, height, &params, &fee_inputs()).expect("claim");
        let child = claim.child.as_ref().unwrap();
        let child_fee = child.output_candidates[0].value;

        // G = Σ recreate fees (all recreate here).
        let g: u64 = claim
            .parent_inputs
            .iter()
            .map(|b| {
                let len = serialize_ergo_box(b).unwrap().len() as i32;
                compute_storage_fee(len, params.storage_fee_factor) as u64
            })
            .sum();

        // Measure parent, child, lean challenger exactly as the builder does.
        let (pc, ps) = measure(
            &claim.parent,
            &claim.parent_inputs,
            &params,
            &ctx_at(height),
            &[],
            None,
        )
        .unwrap();
        let child_resolved = vec![claim.child_input.clone().unwrap()];
        let (cc, cs) =
            measure(child, &child_resolved, &params, &ctx_at(height), &[], None).unwrap();

        let fee_tree = parse_fee_tree().unwrap();
        // Reconstruct the plan to build the challenger.
        let plan = {
            let mut p = classify(&boxes, height, &params, None).unwrap();
            p.sort_by_key(|e| std::cmp::Reverse(e.rent));
            p
        };
        let (lc, lci) = build_lean_challenger(&plan, height, &fee_tree).unwrap();
        let (chc, chs) = measure(&lc, &lci, &params, &ctx_at(height), &[], None).unwrap();

        let cost_ff = FeeFactors {
            parent: pc,
            child: cc,
            challenger: chc,
        };
        let size_ff = FeeFactors {
            parent: ps,
            child: cs,
            challenger: chs,
        };
        let formula = unbeatable_child_fee(
            g,
            fee_inputs().min_relay_fee,
            &cost_ff,
            &size_ff,
            fee_inputs().min_relay_fee,
        )
        .unwrap();
        assert_eq!(
            child_fee, formula,
            "built child fee {child_fee} must EXACTLY equal the unbeatable \
             formula {formula} recomputed against the final measurement \
             (converged on the formula value, no overpay)"
        );
        // And the family asserts unbeatable on both axes.
        assert!(family_is_unbeatable(
            g,
            fee_inputs().min_relay_fee,
            child_fee,
            &cost_ff
        ));
        assert!(family_is_unbeatable(
            g,
            fee_inputs().min_relay_fee,
            child_fee,
            &size_ff
        ));
    }

    #[test]
    fn family_is_unbeatable_after_flooring() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes: Vec<ErgoBox> = (0u8..6)
            .map(|i| aged_box(10_000_000_000, 0, 0x31 + i))
            .collect();
        let claim = build(&boxes, height, &params, &fee_inputs()).expect("claim");
        let child_fee = claim.child.as_ref().unwrap().output_candidates[0].value;
        let parent_fee = fee_inputs().min_relay_fee;

        let g: u64 = claim
            .parent_inputs
            .iter()
            .map(|b| {
                let len = serialize_ergo_box(b).unwrap().len() as i32;
                compute_storage_fee(len, params.storage_fee_factor) as u64
            })
            .sum();
        let (pc, ps) = measure(
            &claim.parent,
            &claim.parent_inputs,
            &params,
            &ctx_at(height),
            &[],
            None,
        )
        .unwrap();
        let child_resolved = vec![claim.child_input.clone().unwrap()];
        let (cc, cs) = measure(
            claim.child.as_ref().unwrap(),
            &child_resolved,
            &params,
            &ctx_at(height),
            &[],
            None,
        )
        .unwrap();
        let fee_tree = parse_fee_tree().unwrap();
        let mut plan = classify(&boxes, height, &params, None).unwrap();
        plan.sort_by_key(|e| std::cmp::Reverse(e.rent));
        let (lc, lci) = build_lean_challenger(&plan, height, &fee_tree).unwrap();
        let (chc, chs) = measure(&lc, &lci, &params, &ctx_at(height), &[], None).unwrap();

        let cost_ff = FeeFactors {
            parent: pc,
            child: cc,
            challenger: chc,
        };
        let size_ff = FeeFactors {
            parent: ps,
            child: cs,
            challenger: chs,
        };
        assert!(
            family_is_unbeatable(g, parent_fee, child_fee, &cost_ff),
            "cost axis must be unbeatable after flooring"
        );
        assert!(
            family_is_unbeatable(g, parent_fee, child_fee, &size_ff),
            "size axis must be unbeatable after flooring"
        );
    }

    #[test]
    fn child_fee_uses_token_burning_lean_challenger() {
        // A batch of full-consume token boxes. The lean challenger burns
        // those tokens (one catch-all, no token outputs) → leaner than our
        // token-preserving parent → smaller feeFactor → a higher, truly
        // unbeatable child fee. Confirm the challenger has exactly ONE
        // output (catch-all) for an all-consume batch, vs our parent's many
        // token boxes — and that the catch-all is a FEE-PROPOSITION output
        // (the only fee-recognized shape a real bidder could use), not P2PK.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        // value < fee (≈56M for a small box) ⇒ full consume; each carries
        // tokens. Use enough value to fund the token box dust.
        let boxes = vec![
            box_with_tokens(40_000_000, 0, 0x41, tokens_from(0, 3)),
            box_with_tokens(40_000_000, 0, 0x42, tokens_from(10, 3)),
            box_with_tokens(40_000_000, 0, 0x43, tokens_from(20, 3)),
        ];
        let mut plan = classify(&boxes, height, &params, None).unwrap();
        plan.sort_by_key(|e| std::cmp::Reverse(e.rent));
        assert!(
            plan.iter().all(|e| matches!(e.kind, PlanKind::Consume)),
            "all must be consume"
        );

        let fee_tree = parse_fee_tree().unwrap();
        let (lc, _lci) = build_lean_challenger(&plan, height, &fee_tree).unwrap();
        // All-consume ⇒ challenger has exactly one (catch-all) output, no
        // tokens (burned).
        assert_eq!(
            lc.output_candidates.len(),
            1,
            "all-consume challenger has one catch-all output"
        );
        assert!(
            lc.output_candidates[0].tokens.is_empty(),
            "challenger burns the tokens"
        );
        // The catch-all is a fee-proposition box (matches the parent fee
        // tree), NOT P2PK — only fee-proposition outputs are counted as fee,
        // so this is the real leanest legal fee-bidding challenger.
        assert_eq!(
            lc.output_candidates[0].ergo_tree_bytes(),
            MAINNET_FEE_PROPOSITION_BYTES,
            "challenger catch-all must be a fee-proposition output, not P2PK"
        );
    }

    #[test]
    fn family_fits_mempool_per_tx_caps() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes: Vec<ErgoBox> = (0u8..4)
            .map(|i| aged_box(10_000_000_000, 0, 0x51 + i))
            .collect();
        let fi = fee_inputs();
        let claim = build(&boxes, height, &params, &fi).expect("claim");
        let psize = serialize_tx(&claim.parent).unwrap().len() as u64;
        assert!(psize <= fi.max_tx_size_bytes as u64);
        let (pc, _) = measure(
            &claim.parent,
            &claim.parent_inputs,
            &params,
            &ctx_at(height),
            &[],
            None,
        )
        .unwrap();
        assert!(pc <= fi.max_tx_cost);
        // A tiny size cap forces a skip (no family fits) — exercises the cap.
        let mut tiny = fee_inputs();
        tiny.max_tx_size_bytes = 50;
        assert!(
            build(&boxes, height, &params, &tiny).is_none(),
            "a 50-byte cap admits nothing"
        );
    }

    #[test]
    fn built_family_passes_validate_transaction_parsed() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes: Vec<ErgoBox> = (0u8..3)
            .map(|i| aged_box(10_000_000_000, 0, 0x61 + i))
            .collect();
        let claim = build(&boxes, height, &params, &fee_inputs()).expect("claim");
        validate(&claim.parent, &claim.parent_inputs, height, &params);
        let child = claim.child.unwrap();
        let child_resolved = vec![claim.child_input.unwrap()];
        validate(&child, &child_resolved, height, &params);
    }

    #[test]
    fn mixed_batch_recreate_and_consume_validates_and_preserves_tokens() {
        // A batched family with BOTH a recreate box and full-consume token
        // boxes. The parent must validate, conserve ERG, give each consume
        // box its own token box (never burning), and chain a valid child.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes = vec![
            aged_box(10_000_000_000, 0, 0x67),                       // recreate
            box_with_tokens(40_000_000, 0, 0x68, tokens_from(0, 3)), // consume
            box_with_tokens(40_000_000, 0, 0x69, tokens_from(20, 2)), // consume
        ];
        let claim = build(&boxes, height, &params, &fee_inputs()).expect("mixed claim");
        assert!(claim.child.is_some());
        assert_eq!(sum_in(&claim.parent_inputs), sum_out(&claim.parent));
        // Each consume box keeps its tokens in its own box (5 tokens total,
        // spread across two token boxes — never aggregated/burned).
        let total_out_tokens: usize = claim
            .parent
            .output_candidates
            .iter()
            .map(|o| o.tokens.len())
            .sum();
        assert_eq!(
            total_out_tokens, 5,
            "all 5 input tokens preserved across token boxes"
        );
        validate(&claim.parent, &claim.parent_inputs, height, &params);
        let child = claim.child.unwrap();
        let child_resolved = vec![claim.child_input.unwrap()];
        validate(&child, &child_resolved, height, &params);
    }

    // ===== lone shapes =====

    #[test]
    fn single_box_is_never_chained() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let claim = build(
            &[aged_box(10_000_000_000, 0, 0x71)],
            height,
            &params,
            &fee_inputs(),
        )
        .expect("lone recreate claim");
        assert!(claim.child.is_none(), "1 box ⇒ no CPFP child");
        assert!(claim.child_input.is_none());
    }

    #[test]
    fn lone_recreate_parent_only_minimal_fee_with_proceeds() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let fi = fee_inputs();
        let claim =
            build(&[aged_box(10_000_000_000, 0, 0x72)], height, &params, &fi).expect("claim");
        assert!(claim.child.is_none());
        // Outputs: [recreate, fee, proceeds].
        assert_eq!(claim.parent.output_candidates.len(), 3);
        // Fee output value == min_relay_fee, locked by the fee proposition.
        let fee_box = &claim.parent.output_candidates[1];
        assert_eq!(fee_box.value, fi.min_relay_fee);
        assert_eq!(fee_box.ergo_tree_bytes(), MAINNET_FEE_PROPOSITION_BYTES);
        // proceeds to the P2PK.
        let proceeds = &claim.parent.output_candidates[2];
        let expected_p2pk = ergo_ser::address::build_p2pk_tree_bytes(&PK).unwrap();
        assert_eq!(proceeds.ergo_tree_bytes(), expected_p2pk.as_slice());
        assert_eq!(sum_in(&claim.parent_inputs), sum_out(&claim.parent));
        validate(&claim.parent, &claim.parent_inputs, height, &params);
    }

    #[test]
    fn lone_recreate_parent_fee_scales_with_per_input_config() {
        // With a non-zero `parent_fee_per_input`, the lone (1-input) recreate
        // parent pays exactly that per-input fee (≥ relay floor) so it is
        // mineable standalone — not the bare relay floor.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let fi = FeeInputs {
            parent_fee_per_input: 10_000_000, // 0.01 ERG
            ..fee_inputs()
        };
        let claim =
            build(&[aged_box(10_000_000_000, 0, 0x72)], height, &params, &fi).expect("claim");
        assert!(claim.child.is_none(), "lone shape has no child");
        // 1 input ⇒ parent fee = max(min_relay, 0.01 ERG * 1) = 0.01 ERG.
        assert_eq!(claim.summary.parent_fee, 10_000_000);
        let fee_box = &claim.parent.output_candidates[1];
        assert_eq!(fee_box.value, 10_000_000);
        assert_eq!(fee_box.ergo_tree_bytes(), MAINNET_FEE_PROPOSITION_BYTES);
        assert_eq!(sum_in(&claim.parent_inputs), sum_out(&claim.parent));
        validate(&claim.parent, &claim.parent_inputs, height, &params);
    }

    #[test]
    fn batched_parent_fee_scales_with_input_count() {
        // The batched parent fee scales with the number of rent boxes claimed
        // (0.01 ERG each). The unbeatable child fee still tops the family up,
        // and the whole family stays valid + affordable.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let fi = FeeInputs {
            parent_fee_per_input: 10_000_000, // 0.01 ERG
            ..fee_inputs()
        };
        let boxes = vec![
            aged_box(10_000_000_000, 0, 0x01),
            aged_box(10_000_000_000, 0, 0x02),
            aged_box(10_000_000_000, 0, 0x03),
        ];
        let claim = build(&boxes, height, &params, &fi).expect("batched claim");
        assert!(claim.child.is_some(), "batched ⇒ CPFP child retained");
        let n = claim.parent_inputs.len() as u64;
        assert!(n >= 2, "stayed batched");
        // parent fee == 0.01 ERG * (boxes actually claimed).
        assert_eq!(claim.summary.parent_fee, 10_000_000 * n);
        assert_eq!(sum_in(&claim.parent_inputs), sum_out(&claim.parent));
        validate(&claim.parent, &claim.parent_inputs, height, &params);
    }

    #[test]
    fn parent_fee_floors_at_min_relay_when_per_input_is_zero() {
        // `parent_fee_per_input = 0` (the test-helper default) collapses the
        // parent fee to exactly the relay floor — the pre-change behavior the
        // other tests assert against.
        let fi = fee_inputs();
        assert_eq!(fi.parent_fee(1), fi.min_relay_fee);
        assert_eq!(fi.parent_fee(7), fi.min_relay_fee);
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let claim =
            build(&[aged_box(10_000_000_000, 0, 0x72)], height, &params, &fi).expect("claim");
        assert_eq!(claim.summary.parent_fee, fi.min_relay_fee);
    }

    #[test]
    fn excessive_parent_fee_per_input_skips_rather_than_emitting_unaffordable() {
        // A per-input parent fee far larger than the box's extractable rent
        // makes the claim unaffordable; the builder must skip it (None), never
        // emit a negative-proceeds or invalid claim.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let fi = FeeInputs {
            parent_fee_per_input: 100_000_000_000, // 100 ERG/input ≫ any rent
            ..fee_inputs()
        };
        let claim = build(&[aged_box(10_000_000_000, 0, 0x72)], height, &params, &fi);
        assert!(
            claim.is_none(),
            "unaffordable parent fee ⇒ skipped, not emitted"
        );
    }

    #[test]
    fn batched_stays_affordable_with_nonzero_parent_fee() {
        // With a non-zero per-input parent fee the batched family is rebuilt and
        // the unbeatable child fee recomputed against the larger parent; the
        // family stays valid with strictly positive proceeds.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let fi = FeeInputs {
            parent_fee_per_input: 10_000_000, // 0.01 ERG/input
            ..fee_inputs()
        };
        let boxes = vec![
            aged_box(10_000_000_000, 0, 0x01),
            aged_box(10_000_000_000, 0, 0x02),
        ];
        let claim = build(&boxes, height, &params, &fi).expect("affordable batched claim");
        // proceeds output is the parent's last output (anchor, fee, proceeds).
        let proceeds = claim.parent.output_candidates.last().unwrap().value;
        assert!(
            proceeds > 0,
            "positive proceeds after the higher parent fee"
        );
        assert_eq!(
            claim.summary.parent_fee,
            10_000_000 * claim.parent_inputs.len() as u64
        );
        assert_eq!(sum_in(&claim.parent_inputs), sum_out(&claim.parent));
        validate(&claim.parent, &claim.parent_inputs, height, &params);
    }

    #[test]
    fn lone_consumed_tokens_to_minimal_box_remaining_to_fee() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        // value < fee, above dust, funds the fee floor.
        let consume = box_with_tokens(10_000_000, 0, 0x73, tokens_from(0, 2));
        let claim = build(&[consume], height, &params, &fee_inputs()).expect("claim");
        assert!(claim.child.is_none());
        // Two outputs: the minimal token box + the fee box (residual). Ergo
        // has no implicit fee, so the fee is an explicit output box.
        assert_eq!(claim.parent.output_candidates.len(), 2);
        let token_box = &claim.parent.output_candidates[0];
        assert_eq!(
            token_box.tokens.len(),
            2,
            "tokens swept into the minimal box"
        );
        let fee_box = &claim.parent.output_candidates[1];
        assert_eq!(fee_box.ergo_tree_bytes(), MAINNET_FEE_PROPOSITION_BYTES);
        // token_box holds only dust; the residual is the fee box.
        assert!(token_box.value < 10_000_000);
        assert_eq!(
            token_box.value + fee_box.value,
            10_000_000,
            "Σ out == value"
        );
        assert!(fee_box.value >= fee_inputs().min_relay_fee);
        validate(&claim.parent, &claim.parent_inputs, height, &params);
    }

    #[test]
    fn lone_consumed_no_tokens_pays_full_value_as_fee_no_token_box() {
        // A full-consume box with NO tokens: there is nothing to preserve, so
        // no token box is built. The single output is a fee-proposition box
        // holding the FULL input value as the miner fee (no leftover P2PK
        // dust). Σ in == Σ out, and it validates.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        // value < fee (small box ⇒ fee ≈ tens of millions), >= min_relay,
        // >= the fee box dust → a single fee output.
        let consume = aged_box(10_000_000, 0, 0x77);
        // Confirm it is classified full-consume (value <= storage fee).
        let mut plan = classify(std::slice::from_ref(&consume), height, &params, None).unwrap();
        plan.sort_by_key(|e| std::cmp::Reverse(e.rent));
        assert!(
            matches!(plan[0].kind, PlanKind::Consume),
            "a small no-token box must be full-consume"
        );

        let claim = build(&[consume], height, &params, &fee_inputs()).expect("claim");
        assert!(claim.child.is_none());
        // Exactly ONE output: the fee box (no token box, no dust P2PK).
        assert_eq!(
            claim.parent.output_candidates.len(),
            1,
            "no-token full-consume produces a single fee output"
        );
        let fee_box = &claim.parent.output_candidates[0];
        assert_eq!(
            fee_box.ergo_tree_bytes(),
            MAINNET_FEE_PROPOSITION_BYTES,
            "the lone output is a fee-proposition box"
        );
        assert!(fee_box.tokens.is_empty(), "no tokens on the fee output");
        // The full input value is the fee — ERG conserved.
        assert_eq!(fee_box.value, 10_000_000, "fee == full input value");
        assert_eq!(sum_in(&claim.parent_inputs), sum_out(&claim.parent));
        assert_eq!(claim.summary.shape, ClaimShape::LoneConsume);
        assert_eq!(claim.summary.num_boxes, 1);
        assert_eq!(claim.summary.parent_fee, 10_000_000);
        assert_eq!(claim.summary.proceeds, 0);
        validate(&claim.parent, &claim.parent_inputs, height, &params);
    }

    #[test]
    fn consumed_box_tokens_never_burned() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let consume = box_with_tokens(10_000_000, 0, 0x74, tokens_from(5, 4));
        let claim = build(&[consume], height, &params, &fee_inputs()).expect("claim");
        let token_box = &claim.parent.output_candidates[0];
        // Every input token appears in the output (never burned).
        assert_eq!(token_box.tokens.len(), 4);
        for t in &tokens_from(5, 4) {
            assert!(
                token_box.tokens.contains(t),
                "token {t:?} must be preserved"
            );
        }
    }

    #[test]
    fn consumed_box_unfundable_is_skipped_not_burned() {
        // A full-consume box whose value can't fund even its token box's
        // dust ⇒ skipped (tokens stay in place, never burned, no claim).
        let params = rent_params(10, 1_250_000);
        let height = 100;
        // 1 nanoERG: below the token box dust floor.
        let tiny = box_with_tokens(1, 0, 0x75, tokens_from(0, 2));
        assert!(
            build(&[tiny], height, &params, &fee_inputs()).is_none(),
            "an unfundable consume box must be skipped, not burned"
        );
    }

    #[test]
    fn token_output_over_max_box_size_is_skipped() {
        // A consume box whose token box exceeds max_box_size ⇒ skipped.
        // 122 tokens is the protocol per-box cap; push max_box_size tiny so
        // even a modest token box overflows.
        let mut params = rent_params(10, 1_250_000);
        params.max_box_size = 64; // smaller than any token-bearing box
        let height = 100;
        let consume = box_with_tokens(10_000_000, 0, 0x76, tokens_from(0, 5));
        assert!(
            build(&[consume], height, &params, &fee_inputs()).is_none(),
            "a token box over max_box_size must be skipped"
        );
    }

    // ===== gating / skip conditions =====

    #[test]
    fn overflow_fee_box_is_skipped() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        // Box large enough that fee wraps i32 negative (paired with a normal
        // box so the set is otherwise batchable). Only the overflow box is
        // dropped; the normal box becomes a lone claim.
        let big = box_with_tokens(10_000_000_000, 0, 0x80, tokens_from(0, 70));
        let len = serialize_ergo_box(&big).unwrap().len() as i32;
        assert!(
            compute_storage_fee(len, params.storage_fee_factor) < 0,
            "must overflow"
        );
        let normal = aged_box(10_000_000_000, 0, 0x81);
        let claim =
            build(&[big, normal], height, &params, &fee_inputs()).expect("normal box claims");
        // Only the non-overflow box is claimed (lone recreate, no child).
        assert_eq!(claim.parent_inputs.len(), 1);
        assert!(claim.child.is_none());
    }

    #[test]
    fn recreate_output_creation_height_is_current_height() {
        let params = rent_params(10, 1_250_000);
        let height = 12_345;
        let claim = build(
            &[aged_box(10_000_000_000, 0, 0x82)],
            height,
            &params,
            &fee_inputs(),
        )
        .expect("claim");
        assert_eq!(
            claim.parent.output_candidates[0].creation_height, height,
            "recreate output must sit at the current height"
        );
    }

    #[test]
    fn reemission_token_box_is_skipped() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let reemission_token_id = [0xEEu8; 32];
        let rules = ReemissionRuleInputs {
            activation_height: 0,
            reemission_token_id,
            pay_to_reemission_tree: ANCHOR_TREE_BYTES.to_vec(),
        };
        let tainted = box_with_tokens(
            10_000_000_000,
            0,
            0x83,
            vec![Token {
                token_id: Digest32::from_bytes(reemission_token_id),
                amount: 1,
            }],
        );
        let claim = build_broadcast_claim(
            &[tainted],
            height,
            &params,
            &PK,
            &ctx_at(height),
            &[],
            Some(&rules),
            &fee_inputs(),
        )
        .expect("no error");
        assert!(
            claim.is_none(),
            "a re-emission-token box must be left unclaimed"
        );
    }

    // ===== affordability / fee loop =====

    #[test]
    fn unaffordable_batch_shrinks_then_skips() {
        // A high min_profit gate that no shrink can satisfy ⇒ None.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes: Vec<ErgoBox> = (0u8..3)
            .map(|i| aged_box(10_000_000_000, 0, 0x90 + i))
            .collect();
        let mut fi = fee_inputs();
        fi.min_profit = u64::MAX; // unsatisfiable
        assert!(
            build(&boxes, height, &params, &fi).is_none(),
            "an unsatisfiable profit gate must yield no claim after shrinking"
        );
    }

    #[test]
    fn fee_loop_terminates_and_stays_affordable() {
        // Normal batch converges within MAX_FEE_ITERS and the proceeds still
        // clear dust + a positive min_profit.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes: Vec<ErgoBox> = (0u8..5)
            .map(|i| aged_box(10_000_000_000, 0, 0xA0 + i))
            .collect();
        let mut fi = fee_inputs();
        fi.min_profit = 100_000_000; // 0.1 ERG floor on proceeds
        let claim = build(&boxes, height, &params, &fi).expect("converges affordably");
        // proceeds is the last output; must clear min_profit.
        let proceeds = claim.parent.output_candidates.last().unwrap();
        assert!(
            proceeds.value >= fi.min_profit,
            "proceeds {} must clear min_profit",
            proceeds.value
        );
        assert_eq!(sum_in(&claim.parent_inputs), sum_out(&claim.parent));
    }

    #[test]
    fn empty_input_yields_none() {
        let params = rent_params(10, 1_250_000);
        assert!(build(&[], 100, &params, &fee_inputs()).is_none());
    }

    #[test]
    fn larger_mixed_batch_converges_within_cap_with_child() {
        // A bigger mixed batch (recreate + many consume) must still converge
        // within MAX_FEE_ITERS and emit a CPFP child (not silently shrink to
        // a lone shape). Guards the fee-loop convergence headroom.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let mut boxes = vec![aged_box(20_000_000_000, 0, 0xB0)];
        for i in 0u8..8 {
            boxes.push(box_with_tokens(
                45_000_000,
                0,
                0xB1 + i,
                tokens_from(i * 5, 2),
            ));
        }
        let claim = build(&boxes, height, &params, &fee_inputs()).expect("converges");
        assert!(
            claim.child.is_some(),
            "a healthy mixed batch must keep its CPFP child"
        );
        assert_eq!(claim.parent_inputs.len(), 9, "no box should be dropped");
        assert_eq!(sum_in(&claim.parent_inputs), sum_out(&claim.parent));
        validate(&claim.parent, &claim.parent_inputs, height, &params);
        let child = claim.child.unwrap();
        let child_resolved = vec![claim.child_input.unwrap()];
        validate(&child, &child_resolved, height, &params);
    }

    // ===== carry-forward #1 =====

    #[test]
    fn zero_measured_fee_factor_is_an_error() {
        let err = checked_fee_factors("cost", 10, 0, 20).unwrap_err();
        match err {
            MiningError::IdComputation { op, reason } => {
                assert_eq!(op, "broadcast_fee_factor");
                assert!(
                    reason.contains("cost") && reason.contains("child") && reason.contains("0")
                );
            }
            other => panic!("expected IdComputation, got {other:?}"),
        }
        // All-positive factors succeed.
        assert!(checked_fee_factors("size", 1, 2, 3).is_ok());
    }

    // ===== Phase 5.1: BroadcastSummary (observability) =====
    //
    // The summary is ADDITIVE: each test re-derives the values from the
    // built family and confirms the summary the builder populated agrees.
    // It never alters shape logic, conservation, the fee loop, or any
    // existing assertion above.

    #[test]
    fn batched_summary_matches_family() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes: Vec<ErgoBox> = (0u8..4)
            .map(|i| aged_box(10_000_000_000, 0, 0xC0 + i))
            .collect();
        let claim = build(&boxes, height, &params, &fee_inputs()).expect("batched claim");
        let s = claim.summary;
        assert_eq!(s.shape, ClaimShape::Batched);
        assert_eq!(s.num_boxes, claim.parent_inputs.len());
        assert_eq!(s.num_boxes, 4);
        // parent_fee is the fee output (min_relay) — second-to-last output is
        // the fee box in the [recreate..., consume..., anchor, fee, proceeds]
        // layout. Assert against BOTH the input constant and the ACTUAL built
        // fee-box value.
        assert_eq!(s.parent_fee, fee_inputs().min_relay_fee);
        let n = claim.parent.output_candidates.len();
        assert_eq!(
            s.parent_fee,
            claim.parent.output_candidates[n - 2].value,
            "parent_fee == the built fee-box output (output[len-2])",
        );
        // child_fee == the CPFP child's single output value == the anchor.
        let child_fee = claim.child.as_ref().unwrap().output_candidates[0].value;
        assert_eq!(s.child_fee, child_fee);
        assert!(s.child_fee > 0, "batched ⇒ a non-zero child fee");
        // proceeds == the last parent output value.
        let proceeds = claim.parent.output_candidates.last().unwrap().value;
        assert_eq!(s.proceeds, proceeds);
        // Conservation cross-check: Σ in == Σ out, and the summary's fees +
        // proceeds are real outputs already counted in that identity.
        assert_eq!(sum_in(&claim.parent_inputs), sum_out(&claim.parent));
    }

    #[test]
    fn lone_recreate_summary_matches_family() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let fi = fee_inputs();
        let claim = build(&[aged_box(10_000_000_000, 0, 0xC8)], height, &params, &fi)
            .expect("lone recreate claim");
        let s = claim.summary;
        assert_eq!(s.shape, ClaimShape::LoneRecreate);
        assert_eq!(s.num_boxes, 1);
        assert_eq!(s.parent_fee, fi.min_relay_fee);
        // Also assert against the ACTUAL built fee-box value — output index 1
        // in the [recreate(0), fee(1), proceeds(2)] layout.
        assert_eq!(
            s.parent_fee, claim.parent.output_candidates[1].value,
            "parent_fee == the built fee-box output (output[1])",
        );
        assert_eq!(s.child_fee, 0, "lone shape ⇒ no child fee");
        // proceeds == the third (proceeds) output of [recreate, fee, proceeds].
        let proceeds = claim.parent.output_candidates[2].value;
        assert_eq!(s.proceeds, proceeds);
        assert!(s.proceeds > 0);
    }

    #[test]
    fn lone_consume_summary_matches_family() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        // value < fee ⇒ full consume; tokens preserved.
        let consume = box_with_tokens(10_000_000, 0, 0xC9, tokens_from(0, 2));
        let claim = build(&[consume], height, &params, &fee_inputs()).expect("lone consume claim");
        let s = claim.summary;
        assert_eq!(s.shape, ClaimShape::LoneConsume);
        assert_eq!(s.num_boxes, 1);
        // No proceeds output on this shape — the residual IS the fee.
        assert_eq!(s.proceeds, 0, "lone-consume has no proceeds output");
        assert_eq!(s.child_fee, 0);
        // parent_fee == the fee box value (output index 1: [token_box, fee]).
        let fee_box = claim.parent.output_candidates[1].value;
        assert_eq!(s.parent_fee, fee_box);
        assert!(s.parent_fee >= fee_inputs().min_relay_fee);
    }

    #[test]
    fn claim_shape_labels_are_stable() {
        // The structured-log/metric field strings are pinned (operators key
        // dashboards off them).
        assert_eq!(ClaimShape::Batched.as_str(), "batched");
        assert_eq!(ClaimShape::LoneRecreate.as_str(), "lone-recreate");
        assert_eq!(ClaimShape::LoneConsume.as_str(), "lone-consume");
    }
}
