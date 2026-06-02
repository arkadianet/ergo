//! Miner-side storage-rent self-claim transaction builder.
//!
//! A node mining its own block may sweep storage-rent-eligible boxes
//! (unspent for at least the storage period) directly into a single
//! zero-fee transaction paying the freed rent to the miner's P2PK. This
//! is the privileged path Scala leaves to external bots: the miner needs
//! no transaction fee to incentivize inclusion because it controls the
//! block.
//!
//! The builder is pure (no I/O): callers pass the fully-resolved
//! `ErgoBox`es (enumerated via the indexer, then resolved from state) and
//! receive a [`RentClaim`] holding the transaction plus its resolved
//! inputs in tx-input order, ready for `validate_transaction_parsed`.
//!
//! Consensus contract mirrored from `ErgoInterpreter.checkExpiredBox`
//! (see `ergo-validation/src/tx/script.rs::check_storage_rent`):
//! - input spending proof is empty,
//! - context-extension variable 127 names the recreated-output index,
//! - `box_age >= storage_period`,
//! - if `value > storageFee`: recreate an output preserving
//!   script/tokens/registers with `value >= value - fee` at the current
//!   height (miner keeps the `fee`),
//! - if `value <= storageFee`: the whole box (value + tokens) is seized.
//!
//! `storageFee = storage_fee_factor *(i32 wrapping)* box_bytes_len`. Boxes
//! whose fee wraps negative are consensus-uncollectable and MUST be
//! skipped — including one would fork the block from Scala.
//!
//! Contract: the builder only ever returns transactions the validator
//! will accept. A box is silently skipped when claiming it would produce
//! an output the validator rejects — recreate value below the per-byte
//! min-value (dust) floor, an output past `max_box_size`, or a count past
//! `max_claims`. Excess seized tokens past what fits one P2PK output are
//! burned. If the total proceeds cannot clear the dust floor, no claim is
//! produced.

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::build_p2pk_tree_bytes;
use ergo_ser::ergo_box::{serialize_ergo_box, write_ergo_box_candidate, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{read_ergo_tree, ErgoTree};
use ergo_ser::header::Header;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use ergo_ser::transaction::{write_transaction, Transaction};
use ergo_validation::storage_rent::compute_storage_fee;
use ergo_validation::{
    validate_transaction_parsed, CheckedTransaction, CostAccumulator, ProtocolParams,
    TransactionContext, TxValidationCtx,
};

use crate::error::MiningError;

/// `Constants.StorageIndexVarId` — the context-extension key carrying the
/// recreated-output index on a storage-rent input. Mirrors the private
/// `STORAGE_INDEX_VAR_ID` in `ergo-validation/src/tx/script.rs`.
pub const STORAGE_RENT_OUTPUT_INDEX_VAR_ID: u8 = 127;

/// Per-box token cap (Scala/ergo-ser wire format writes the token count as
/// a single byte). The aggregate P2PK output is further trimmed to fit
/// `max_box_size`; see [`build_rent_claim`].
const MAX_TOKENS_PER_BOX: usize = 255;

/// A built storage-rent claim: the transaction plus the resolved input
/// boxes (in tx-input order) the caller feeds to
/// `validate_transaction_parsed`.
#[derive(Debug, Clone)]
pub struct RentClaim {
    /// The zero-fee rent-claim transaction.
    pub tx: Transaction,
    /// The boxes actually claimed, in `tx.inputs` order. Boxes skipped
    /// because they are too young, fee-overflowed, would recreate below
    /// the dust floor, would exceed `max_box_size`, or fell past
    /// `max_claims` are absent.
    pub resolved_inputs: Vec<ErgoBox>,
}

/// Build a single zero-fee storage-rent claim sweeping up to `max_claims`
/// of the `eligible` boxes to the miner's P2PK. Returns `None` when no box
/// is claimable.
///
/// `params` supplies the consensus parameters that gate claimability:
/// `storage_period`, `storage_fee_factor`, `min_value_per_byte`, and
/// `max_box_size`. `max_claims` bounds how many boxes (and thus outputs)
/// one claim may carry; it is clamped to `i16::MAX` so every var-127
/// output index fits the wire format.
pub fn build_rent_claim(
    eligible: &[ErgoBox],
    current_height: u32,
    params: &ProtocolParams,
    max_claims: usize,
    miner_pubkey: &[u8; 33],
) -> Result<Option<RentClaim>, MiningError> {
    // Clamp so every var-127 output index fits the i16 the wire uses.
    let max_claims = max_claims.min(i16::MAX as usize);
    let max_box_size = params.max_box_size as usize;

    // Destination of each claimed box's value, decided in one pass so the
    // aggregate P2PK output index (which full-consume inputs name in var
    // 127) is known before the inputs are built.
    enum Dest {
        /// Recreate branch: var 127 names this recreated-output index.
        Recreate(usize),
        /// Full-consume branch: var 127 names the aggregate P2PK output.
        FullConsume,
    }

    let mut claimed: Vec<(&ErgoBox, Dest)> = Vec::new();
    let mut recreated: Vec<ErgoBoxCandidate> = Vec::new();
    // Value swept to the miner; plus tokens seized from full-consume boxes.
    let mut p2pk_value: u64 = 0;
    let mut p2pk_tokens: Vec<Token> = Vec::new();

    for b in eligible {
        if claimed.len() >= max_claims {
            break;
        }

        // Eligibility: box must be old enough. The validator enforces
        // `box_age >= storage_period`; skip anything younger so we never
        // build an input the validator would reject.
        let box_age = current_height.saturating_sub(b.candidate.creation_height);
        if box_age < params.storage_period {
            continue;
        }

        // `storageFee = storage_fee_factor *(i32 wrapping)* box_bytes_len`.
        // A non-positive fee is either nothing to collect (factor 0) or an
        // i32 overflow (box_bytes_len beyond the wrap point), which is
        // consensus-uncollectable — Scala would reject a claim on it, so
        // skip it to keep the block fork-free.
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
            // Recreate branch: output preserves script/tokens/registers,
            // sits at the current height, carries `value - fee`; the miner
            // keeps `fee`.
            let recreated_value = b.candidate.value - fee;
            let output_idx = recreated.len();
            let recreated_box = ErgoBoxCandidate::from_trusted_raw_parts(
                recreated_value,
                b.candidate.ergo_tree().clone(),
                b.candidate.ergo_tree_bytes().to_vec(),
                current_height,
                b.candidate.tokens.clone(),
                b.candidate.additional_registers.clone(),
                b.candidate.register_bytes().to_vec(),
            );
            // The recreated output must clear the validator's box rules:
            // the per-byte min-value (dust) floor and max-box-size. If
            // `value - fee` is below dust (or it somehow exceeds the box
            // cap), the box is uncollectable via recreate — skip it rather
            // than emit a block the validator (and Scala) would reject.
            let (min_value, box_size) =
                box_min_value_and_size(&recreated_box, output_idx, params.min_value_per_byte)?;
            if recreated_value < min_value || box_size > max_box_size {
                continue;
            }
            recreated.push(recreated_box);
            p2pk_value = p2pk_value.saturating_add(fee);
            claimed.push((b, Dest::Recreate(output_idx)));
        } else {
            // Full-consume branch: `value <= fee`. The whole box — value
            // and tokens — is seized into the aggregate P2PK output. Tokens
            // beyond the wire cap are dropped here; the aggregate is
            // further trimmed to `max_box_size` below.
            p2pk_value = p2pk_value.saturating_add(b.candidate.value);
            for t in &b.candidate.tokens {
                if p2pk_tokens.len() >= MAX_TOKENS_PER_BOX {
                    break;
                }
                p2pk_tokens.push(t.clone());
            }
            claimed.push((b, Dest::FullConsume));
        }
    }

    if claimed.is_empty() {
        return Ok(None);
    }

    // The aggregate P2PK output sits right after every recreated box, so
    // recreate inputs' var-127 indices stay valid and full-consume inputs
    // name this index.
    let p2pk_index = recreated.len();
    let p2pk_tree = parse_p2pk_tree(miner_pubkey)?;

    // Trim seized tokens until the P2PK output fits max_box_size; excess
    // tokens are burned (consensus-legal: outputs may carry fewer tokens
    // than inputs).
    let mut p2pk_box = build_p2pk_box(p2pk_value, &p2pk_tree, current_height, p2pk_tokens.clone())?;
    loop {
        let (_, box_size) =
            box_min_value_and_size(&p2pk_box, p2pk_index, params.min_value_per_byte)?;
        if box_size <= max_box_size || p2pk_tokens.is_empty() {
            break;
        }
        p2pk_tokens.pop();
        p2pk_box = build_p2pk_box(p2pk_value, &p2pk_tree, current_height, p2pk_tokens.clone())?;
    }

    // The aggregate output must clear the min-value floor and box cap. With
    // any recreate box present the freed fees keep it well above dust; this
    // only bites when every claimed box is a negligible full-consume box.
    let (p2pk_min_value, p2pk_size) =
        box_min_value_and_size(&p2pk_box, p2pk_index, params.min_value_per_byte)?;
    if p2pk_value < p2pk_min_value || p2pk_size > max_box_size {
        return Ok(None);
    }

    let mut output_candidates = recreated;
    output_candidates.push(p2pk_box);

    let mut inputs: Vec<Input> = Vec::with_capacity(claimed.len());
    let mut resolved_inputs: Vec<ErgoBox> = Vec::with_capacity(claimed.len());
    for (b, dest) in claimed {
        let output_idx = match dest {
            Dest::Recreate(i) => i,
            Dest::FullConsume => p2pk_index,
        };
        inputs.push(rent_input(b, output_idx)?);
        resolved_inputs.push(b.clone());
    }

    Ok(Some(RentClaim {
        tx: Transaction {
            inputs,
            data_inputs: Vec::new(),
            output_candidates,
        },
        resolved_inputs,
    }))
}

/// Build a storage-rent self-claim sized to FILL the block budget: sweep
/// the oldest `eligible` boxes (up to `max_claims`), then shrink the count
/// until the VALIDATED claim's block cost and serialized size both fall
/// within `cost_ceiling` / `size_ceiling`. Returns the validated claim
/// transaction paired with its exact block cost and serialized size, or
/// `None` when nothing claimable fits.
///
/// The cost/size are measured by validating each attempt through
/// `validate_transaction_parsed` — the same path the block validator uses —
/// so the bound matches what a peer computes. There is no consensus per-tx
/// size limit; only the block caps the caller passes here gate a self-mined
/// tx. The returned claim is GUARANTEED within the ceilings (or `None`), so
/// the pinned `[coinbase, rent]` prefix can never exceed the block budget.
/// The shrink is proportional to the measured per-claim cost/size, so it
/// converges in one or two attempts.
#[allow(clippy::too_many_arguments)]
pub fn build_budget_bounded_rent_claim(
    eligible: &[ErgoBox],
    current_height: u32,
    params: &ProtocolParams,
    max_claims: usize,
    miner_pubkey: &[u8; 33],
    ctx: &TransactionContext,
    last_headers: &[Header],
    cost_ceiling: u64,
    size_ceiling: u64,
) -> Result<Option<(CheckedTransaction, u64, u64)>, MiningError> {
    // Cap on the number of CLAIMABLE boxes. `build_rent_claim` caps on
    // claims (skipping unclaimable boxes), so shrinking this directly drops
    // claims — keeping the proportional step below accurate even when the
    // eligible set interleaves unclaimable (overflow/dust/too-young) boxes.
    let mut cap = max_claims;
    loop {
        if cap == 0 {
            return Ok(None);
        }
        let claim = match build_rent_claim(eligible, current_height, params, cap, miner_pubkey)? {
            Some(c) => c,
            None => return Ok(None),
        };
        let claimed = claim.resolved_inputs.len();

        let mut w = VlqWriter::new();
        write_transaction(&mut w, &claim.tx).map_err(|e| MiningError::IdComputation {
            op: "serialize_rent_tx",
            reason: format!("{e:?}"),
        })?;
        let bytes = w.result();
        let size = bytes.len() as u64;

        // Measure the claim's exact block cost with a RECORDING-ONLY
        // accumulator. The first (widest) attempt may deliberately exceed
        // `max_block_cost`; an enforcing accumulator would abort here
        // instead of letting us shrink, breaking the fit-or-None contract.
        // The block caps are enforced by `cost_ceiling`/`size_ceiling`
        // below (both < max_block_cost), so the returned claim always fits.
        let mut cost_acc = CostAccumulator::recording_only();
        let checked = {
            let mut cx = TxValidationCtx {
                ctx,
                params,
                cost: &mut cost_acc,
                last_headers,
            };
            validate_transaction_parsed(
                claim.tx.clone(),
                &bytes,
                claim.resolved_inputs,
                Vec::new(),
                false,
                &mut cx,
            )
            .map_err(|e| MiningError::IdComputation {
                op: "validate_rent_tx",
                reason: format!("{e:?}"),
            })?
        };
        let cost = cost_acc.total_block_cost();

        if cost <= cost_ceiling && size <= size_ceiling {
            return Ok(Some((checked, cost, size)));
        }
        if claimed <= 1 {
            // Even a single claim doesn't fit the (pathologically small)
            // budget — produce no rent rather than an over-budget block.
            return Ok(None);
        }

        // Shrink the claimable cap proportionally toward whichever ceiling is
        // exceeded, keyed off the measured per-CLAIM cost/size (the actual
        // `claimed` count, not the raw prefix) so it never overshrinks past
        // a fitting size.
        let per_cost = (cost / claimed as u64).max(1);
        let per_size = (size / claimed as u64).max(1);
        let drop_cost = cost.saturating_sub(cost_ceiling) / per_cost;
        let drop_size = size.saturating_sub(size_ceiling) / per_size;
        let drop = drop_cost.max(drop_size).max(1) as usize;
        cap = claimed.saturating_sub(drop).max(1);
    }
}

/// Build a storage-rent input for `b`: its real `box_id`, an empty
/// spending proof, and context-extension variable 127 naming the
/// recreated/destination output index.
fn rent_input(b: &ErgoBox, output_idx: usize) -> Result<Input, MiningError> {
    let box_id = b.box_id().map_err(|e| MiningError::IdComputation {
        op: "rent_input_box_id",
        reason: format!("{e:?}"),
    })?;
    // The wire format stores var 127 as a Short; bound the conversion
    // rather than silently wrapping. `max_claims` already keeps indices in
    // range, so this only trips on a programming error.
    let idx = i16::try_from(output_idx).map_err(|_| MiningError::IdComputation {
        op: "rent_output_index",
        reason: format!("output index {output_idx} exceeds i16::MAX"),
    })?;
    let mut ext = ContextExtension::empty();
    ext.values.insert(
        STORAGE_RENT_OUTPUT_INDEX_VAR_ID,
        (SigmaType::SShort, SigmaValue::Short(idx)),
    );
    let spending_proof =
        SpendingProof::new(Vec::new(), ext).map_err(|e| MiningError::IdComputation {
            op: "rent_input_spending_proof",
            reason: format!("{e:?}"),
        })?;
    Ok(Input {
        box_id,
        spending_proof,
    })
}

/// Parse the canonical (non-segregated) P2PK tree for `miner_pubkey`. Rent
/// proceeds go to a plain P2PK — NOT the delayed miner-reward script (the
/// 720-block delay is an emission/fee-proposition rule, not a rent rule).
fn parse_p2pk_tree(miner_pubkey: &[u8; 33]) -> Result<ErgoTree, MiningError> {
    let bytes = build_p2pk_tree_bytes(miner_pubkey).map_err(|e| MiningError::IdComputation {
        op: "rent_p2pk_tree",
        reason: format!("{e:?}"),
    })?;
    let mut r = VlqReader::new(&bytes);
    read_ergo_tree(&mut r).map_err(|e| MiningError::Decode {
        op: "rent_p2pk_tree_parse",
        reason: format!("{e:?}"),
    })
}

fn build_p2pk_box(
    value: u64,
    tree: &ErgoTree,
    height: u32,
    tokens: Vec<Token>,
) -> Result<ErgoBoxCandidate, MiningError> {
    ErgoBoxCandidate::new(
        value,
        tree.clone(),
        height,
        tokens,
        AdditionalRegisters::empty(),
    )
    .map_err(|e| MiningError::IdComputation {
        op: "rent_p2pk_box",
        reason: format!("{e:?}"),
    })
}

/// Mirror of `ergo-validation`'s `serialized_box_size` + min-value rule:
/// the full on-chain box length is the candidate body plus the 32-byte
/// transaction id and the VLQ-`u16` output index, and the min value is
/// that length times `min_value_per_byte`.
fn box_min_value_and_size(
    candidate: &ErgoBoxCandidate,
    output_index: usize,
    min_value_per_byte: u64,
) -> Result<(u64, usize), MiningError> {
    let mut w = VlqWriter::new();
    write_ergo_box_candidate(&mut w, candidate).map_err(|e| MiningError::IdComputation {
        op: "rent_box_size",
        reason: format!("{e:?}"),
    })?;
    let mut idx_w = VlqWriter::new();
    idx_w.put_u16(output_index as u16);
    let box_size = w.result().len() + 32 + idx_w.result().len();
    let min_value = (box_size as u64).saturating_mul(min_value_per_byte);
    Ok((min_value, box_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_ser::transaction::write_transaction;
    use ergo_validation::{
        validate_transaction_parsed, CostAccumulator, JitCost, ProtocolParams, TransactionContext,
        TxValidationCtx, ValidationError,
    };

    // ----- helpers -----

    /// secp256k1 generator point, compressed — a valid P2PK pubkey.
    const MINER_PK: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];

    /// Generous claim cap for tests that don't exercise the bound.
    const CLAIMS: usize = 64;

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

    fn aged_box(value: u64, creation_height: u32, seed: u8) -> ErgoBox {
        box_with_tokens(value, creation_height, seed, vec![])
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

    fn tokens_from(start: u8, n: u8) -> Vec<Token> {
        (0..n)
            .map(|i| Token {
                token_id: Digest32::from_bytes([start.wrapping_add(i); 32]),
                amount: 1,
            })
            .collect()
    }

    /// Mainnet-default params with the storage period overridden so test
    /// boxes age in at small heights.
    fn rent_params(storage_period: u32, storage_fee_factor: i32) -> ProtocolParams {
        let mut p = ProtocolParams::mainnet_default();
        p.storage_period = storage_period;
        p.storage_fee_factor = storage_fee_factor;
        p
    }

    /// Run a built claim through the real consensus validator's rent path.
    /// `Ok(())` means the block-level validator would accept the tx.
    fn validate_rent(
        claim: &RentClaim,
        height: u32,
        params: &ProtocolParams,
    ) -> Result<(), ValidationError> {
        let mut w = VlqWriter::new();
        write_transaction(&mut w, &claim.tx).unwrap();
        let bytes = w.result();

        let ctx = TransactionContext {
            height,
            miner_pubkey: MINER_PK,
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        };
        let mut cost =
            CostAccumulator::new(JitCost::from_block_cost(params.max_block_cost).unwrap());
        let mut cx = TxValidationCtx {
            ctx: &ctx,
            params,
            cost: &mut cost,
            last_headers: &[],
        };
        validate_transaction_parsed(
            claim.tx.clone(),
            &bytes,
            claim.resolved_inputs.clone(),
            Vec::new(),
            false,
            &mut cx,
        )
        .map(|_| ())
    }

    /// Extract the var-127 (output index) value from a rent input.
    fn var127(input: &Input) -> i16 {
        match input
            .spending_proof
            .extension
            .values
            .get(&STORAGE_RENT_OUTPUT_INDEX_VAR_ID)
        {
            Some((_, SigmaValue::Short(idx))) => *idx,
            other => panic!("expected a Short var-127, got {other:?}"),
        }
    }

    fn box_size_on_chain(candidate: &ErgoBoxCandidate, index: usize) -> usize {
        box_min_value_and_size(candidate, index, 0).unwrap().1
    }

    // ----- happy path -----

    #[test]
    fn single_recreate_box_builds_validatable_claim() {
        // 10-ERG box, far above its rent fee → recreate branch. The built
        // claim must pass the real consensus validator.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let box1 = aged_box(10_000_000_000, 0, 0xAA);

        let claim = build_rent_claim(&[box1], height, &params, CLAIMS, &MINER_PK)
            .unwrap()
            .expect("a 10-ERG aged box must produce a claim");

        validate_rent(&claim, height, &params).expect("rent claim must pass consensus validation");
    }

    #[test]
    fn full_consume_box_builds_validatable_claim() {
        // Value above dust but below the rent fee (~56M nanoERG for a small
        // box at the default factor) → the whole box is seized to the miner
        // P2PK; no recreated output.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let box1 = aged_box(1_000_000, 0, 0xBB);

        let claim = build_rent_claim(&[box1], height, &params, CLAIMS, &MINER_PK)
            .unwrap()
            .expect("a sub-fee aged box must be fully consumed into a claim");

        assert_eq!(claim.tx.inputs.len(), 1);
        assert_eq!(claim.tx.output_candidates.len(), 1);
        validate_rent(&claim, height, &params)
            .expect("full-consume claim must pass consensus validation");
    }

    // ----- consensus fork-safety: i32 overflow -----

    #[test]
    fn fee_overflow_box_is_skipped() {
        // A box large enough that `box_bytes_len * factor` wraps i32
        // negative is consensus-uncollectable (check_storage_rent would
        // demand an impossible output value). Including it would fork the
        // block from Scala, so the builder must skip it.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let big = box_with_tokens(10_000_000_000, 0, 0xC0, tokens_from(0, 70));

        let bytes_len = serialize_ergo_box(&big).unwrap().len() as i32;
        assert!(
            bytes_len >= 1718,
            "test box must exceed the i32 wrap point, got {bytes_len} bytes"
        );
        assert!(
            compute_storage_fee(bytes_len, params.storage_fee_factor) < 0,
            "test box must overflow the i32 storage fee"
        );

        assert!(
            build_rent_claim(&[big], height, &params, CLAIMS, &MINER_PK)
                .unwrap()
                .is_none(),
            "a fee-overflow box must be skipped, not claimed",
        );
    }

    #[test]
    fn second_wrap_positive_fee_box_is_claimed() {
        // A box whose `box_bytes_len * factor` overflows i32 but lands back
        // positive yields the SAME wrapped fee in Scala (Int*Int), so it is
        // collectable and fork-safe. Only `fee <= 0` boxes are skipped.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let big = box_with_tokens(10_000_000_000, 0, 0xC2, tokens_from(0, 104));

        let bytes_len = serialize_ergo_box(&big).unwrap().len() as i32;
        assert!(
            (bytes_len as i64) * (params.storage_fee_factor as i64) > i32::MAX as i64,
            "test box must overflow i32 at least once"
        );
        assert!(
            compute_storage_fee(bytes_len, params.storage_fee_factor) > 0,
            "test box must land back positive after wrapping"
        );

        let claim = build_rent_claim(&[big], height, &params, CLAIMS, &MINER_PK)
            .unwrap()
            .expect("a second-wrap-positive box is collectable and must be claimed");
        validate_rent(&claim, height, &params)
            .expect("second-wrap-positive claim must pass consensus validation");
    }

    // ----- skip conditions -----

    #[test]
    fn too_young_box_is_skipped() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let young = aged_box(10_000_000_000, 95, 0xE0); // age 5 < 10

        assert!(
            build_rent_claim(&[young], height, &params, CLAIMS, &MINER_PK)
                .unwrap()
                .is_none(),
            "a box younger than the storage period must be skipped",
        );
    }

    #[test]
    fn recreate_below_dust_floor_is_skipped() {
        // A huge min-value-per-byte pushes the recreated output's dust
        // floor above `value - fee`, so the box is uncollectable via
        // recreate and must be skipped (not emitted as an invalid output).
        let mut params = rent_params(10, 1_250_000);
        params.min_value_per_byte = 1_000_000_000; // ~tens of ERG floor
        let height = 100;
        let box1 = aged_box(10_000_000_000, 0, 0xD7);

        assert!(
            build_rent_claim(&[box1], height, &params, CLAIMS, &MINER_PK)
                .unwrap()
                .is_none(),
            "a recreate that would fall below the dust floor must be skipped",
        );
    }

    #[test]
    fn all_tiny_full_consume_below_dust_yields_none() {
        // Pure full-consume whose total seized value cannot clear the P2PK
        // dust floor → nothing worth claiming.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let tiny = aged_box(1, 0, 0xD8); // 1 nanoERG, value < fee, < dust

        assert!(
            build_rent_claim(&[tiny], height, &params, CLAIMS, &MINER_PK)
                .unwrap()
                .is_none(),
            "sub-dust total proceeds must yield no claim",
        );
    }

    #[test]
    fn claims_are_capped_at_max_claims() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes: Vec<ErgoBox> = (0..10)
            .map(|i| aged_box(10_000_000_000, 0, 0x10 + i as u8))
            .collect();

        let claim = build_rent_claim(&boxes, height, &params, 3, &MINER_PK)
            .unwrap()
            .expect("claimable");
        assert_eq!(
            claim.tx.inputs.len(),
            3,
            "claims must be capped at max_claims"
        );
        assert_eq!(claim.resolved_inputs.len(), 3);
        validate_rent(&claim, height, &params).expect("capped claim must validate");
    }

    // ----- mixed branches + invariants -----

    #[test]
    fn mixed_recreate_and_full_consume_validates_and_indexes_correctly() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let recreate = aged_box(10_000_000_000, 0, 0xD0); // value ≫ fee
        let consume = aged_box(1_000_000, 0, 0xD1); // value < fee

        let claim = build_rent_claim(&[recreate, consume], height, &params, CLAIMS, &MINER_PK)
            .unwrap()
            .expect("both boxes are claimable");

        // outputs = [recreated_box, aggregate_p2pk]; two inputs.
        assert_eq!(claim.tx.inputs.len(), 2);
        assert_eq!(claim.resolved_inputs.len(), 2);
        assert_eq!(claim.tx.output_candidates.len(), 2);

        // var-127 indices: recreate input → output 0; full-consume → P2PK (1).
        assert_eq!(var127(&claim.tx.inputs[0]), 0);
        assert_eq!(var127(&claim.tx.inputs[1]), 1);

        validate_rent(&claim, height, &params)
            .expect("mixed-branch claim must pass consensus validation");
    }

    #[test]
    fn claim_is_zero_fee() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let claim = build_rent_claim(
            &[
                aged_box(10_000_000_000, 0, 0xF0),
                aged_box(2_000_000, 0, 0xF1),
            ],
            height,
            &params,
            CLAIMS,
            &MINER_PK,
        )
        .unwrap()
        .expect("claimable");

        let in_sum: u64 = claim
            .resolved_inputs
            .iter()
            .map(|b| b.candidate.value)
            .sum();
        let out_sum: u64 = claim.tx.output_candidates.iter().map(|o| o.value).sum();
        assert_eq!(in_sum, out_sum, "rent claim must have zero transaction fee");
    }

    #[test]
    fn full_consume_seizes_tokens_into_p2pk() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        // value < fee → full consume; carries two tokens.
        let consume = box_with_tokens(1_000_000, 0, 0xC1, tokens_from(0, 2));

        let claim = build_rent_claim(&[consume], height, &params, CLAIMS, &MINER_PK)
            .unwrap()
            .expect("claimable");

        let p2pk = claim.tx.output_candidates.last().unwrap();
        assert_eq!(
            p2pk.tokens.len(),
            2,
            "seized tokens must land in the P2PK box"
        );
        validate_rent(&claim, height, &params)
            .expect("token-seizing claim must pass consensus validation");
    }

    #[test]
    fn seized_tokens_are_trimmed_to_fit_max_box_size() {
        // Four full-consume boxes carrying 180 distinct tokens in total —
        // more than one P2PK output can hold under max_box_size (~120). The
        // aggregate must be trimmed (excess burned) so the output is valid.
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes = vec![
            box_with_tokens(1_000_000, 0, 0xA1, tokens_from(0, 45)),
            box_with_tokens(1_000_000, 0, 0xA2, tokens_from(45, 45)),
            box_with_tokens(1_000_000, 0, 0xA3, tokens_from(90, 45)),
            box_with_tokens(1_000_000, 0, 0xA4, tokens_from(135, 45)),
        ];

        let claim = build_rent_claim(&boxes, height, &params, CLAIMS, &MINER_PK)
            .unwrap()
            .expect("claimable");

        let p2pk = claim.tx.output_candidates.last().unwrap();
        assert!(
            p2pk.tokens.len() < 180,
            "excess tokens must be trimmed, got {}",
            p2pk.tokens.len()
        );
        assert!(
            box_size_on_chain(p2pk, claim.tx.output_candidates.len() - 1)
                <= params.max_box_size as usize,
            "the P2PK output must fit max_box_size",
        );
        validate_rent(&claim, height, &params).expect("trimmed claim must validate");
    }

    #[test]
    fn p2pk_output_targets_the_canonical_miner_address() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let claim = build_rent_claim(
            &[aged_box(10_000_000_000, 0, 0xAB)],
            height,
            &params,
            CLAIMS,
            &MINER_PK,
        )
        .unwrap()
        .expect("claimable");

        let expected = ergo_ser::address::build_p2pk_tree_bytes(&MINER_PK).unwrap();
        let p2pk = claim.tx.output_candidates.last().unwrap();
        assert_eq!(
            p2pk.ergo_tree_bytes(),
            expected.as_slice(),
            "rent proceeds must go to the canonical P2PK tree (not the segregated P2S form)",
        );
    }

    // ----- budget bounding (fill-the-block) -----

    #[test]
    fn budget_bounded_claim_shrinks_to_fit_then_validates() {
        let params = rent_params(10, 1_250_000);
        let height = 100;
        let boxes: Vec<ErgoBox> = (0u8..10)
            .map(|i| aged_box(10_000_000_000, 0, 0x40 + i))
            .collect();
        let ctx = TransactionContext {
            height,
            miner_pubkey: MINER_PK,
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        };

        // A cost ceiling that fits only a few of the ~2.1k-cost claims must
        // shrink the claim, and the validated result must respect it.
        let (checked, cost, _size) = build_budget_bounded_rent_claim(
            &boxes,
            height,
            &params,
            10,
            &MINER_PK,
            &ctx,
            &[],
            20_000,
            u64::MAX,
        )
        .unwrap()
        .expect("at least one claim fits");
        assert!(
            cost <= 20_000,
            "validated cost {cost} must be within the ceiling"
        );
        let n = checked.transaction().inputs.len();
        assert!(
            (1..10).contains(&n),
            "claim must shrink below all 10 boxes, got {n}"
        );

        // A generous budget sweeps every eligible box.
        let (full, _, _) = build_budget_bounded_rent_claim(
            &boxes,
            height,
            &params,
            10,
            &MINER_PK,
            &ctx,
            &[],
            u64::MAX,
            u64::MAX,
        )
        .unwrap()
        .expect("claimable");
        assert_eq!(
            full.transaction().inputs.len(),
            10,
            "a generous budget claims every eligible box",
        );
    }

    #[test]
    fn oversized_initial_claim_shrinks_instead_of_erroring() {
        // A tiny max_block_cost so the widest initial claim's cost exceeds
        // it. An enforcing accumulator would abort validation here (the
        // fit-or-None contract bug); the recording-only path must instead
        // measure the cost and shrink to a fitting claim.
        let mut params = rent_params(10, 1_250_000);
        params.max_block_cost = 25_000; // a 10-box claim costs ~31k
        let height = 100;
        let boxes: Vec<ErgoBox> = (0u8..10)
            .map(|i| aged_box(10_000_000_000, 0, 0x60 + i))
            .collect();
        let ctx = TransactionContext {
            height,
            miner_pubkey: MINER_PK,
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 3,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        };

        let (checked, cost, _size) = build_budget_bounded_rent_claim(
            &boxes,
            height,
            &params,
            10,
            &MINER_PK,
            &ctx,
            &[],
            25_000,
            u64::MAX,
        )
        .expect("must not error on an oversized initial claim")
        .expect("a smaller fitting claim exists");
        assert!(
            cost <= 25_000,
            "returned claim cost {cost} must respect the ceiling"
        );
        assert!(
            checked.transaction().inputs.len() < 10,
            "claim must have shrunk below all 10 boxes"
        );
    }
}
