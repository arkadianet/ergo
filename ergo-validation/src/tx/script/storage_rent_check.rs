use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::Transaction;

use crate::context::ProtocolParams;

/// Storage rent variable ID in context extension (Scala: Constants.StorageIndexVarId).
pub(super) const STORAGE_INDEX_VAR_ID: u8 = 127;

/// JIT cost charged for a storage rent check (Scala: Constants.StorageContractCost).
pub(super) const STORAGE_CONTRACT_COST: u64 = 50;

/// Predicate: a spending input opts into the storage-rent path
/// when ALL three conditions hold simultaneously. Scala parity:
/// `ErgoInterpreter.verify` (`ergo-wallet/.../ErgoInterpreter.scala`)
/// — the `hasEnoughTimeToBeSpent && proof.length == 0 &&
/// extension.values.contains(varId)` triple inside the `verify`
/// branch.
///
/// The eligibility threshold is **inclusive at the boundary**:
/// `box_age == storage_period` is sufficient (Scala uses `>=`),
/// so a box created at height 0 becomes eligible at exactly height
/// `storage_period` (mainnet: 1_051_200, ≈ 4 years at 2 min/block).
///
/// Multiple consecutive periods are all eligible — Scala does not
/// reset eligibility after the first rent collection because
/// `box_age` is monotone in the on-chain UTXO state (the rent
/// re-creates the box with `creation_height = current_height`,
/// which immediately drops `box_age` to zero in the recreated UTXO,
/// not in the about-to-be-spent input).
pub(super) fn is_storage_rent_eligible(
    box_age: u32,
    storage_period: u32,
    proof_empty: bool,
    has_storage_var: bool,
) -> bool {
    box_age >= storage_period && proof_empty && has_storage_var
}

/// Check if a storage-rent spend is valid.
///
/// Matches Scala's `ErgoInterpreter.checkExpiredBox`. The storage fee
/// calculation uses i32 wrapping multiplication to replicate Scala's
/// Int overflow behavior (see ergoplatform/ergo#2251).
pub(super) fn check_storage_rent(
    input_box: &ErgoBox,
    extension: &ergo_ser::input::ContextExtension,
    tx: &Transaction,
    current_height: u32,
    params: &ProtocolParams,
) -> bool {
    // Get output index from context extension variable 127
    let output_idx = match extension.values.get(&STORAGE_INDEX_VAR_ID) {
        Some((_, ergo_ser::sigma_value::SigmaValue::Short(idx))) => *idx as usize,
        Some((_, ergo_ser::sigma_value::SigmaValue::Int(idx))) => *idx as usize,
        _ => return false,
    };

    let output = match tx.output_candidates.get(output_idx) {
        Some(o) => o,
        None => return false,
    };

    // Compute box size (serialized bytes length)
    let box_bytes_len = match ergo_ser::ergo_box::serialize_ergo_box(input_box) {
        Ok(bytes) => bytes.len() as i32,
        Err(e) => {
            tracing::warn!(error = ?e, "storage rent: input box serialization failed; treating as not rent-eligible");
            return false;
        }
    };

    // i32 wrapping multiplication to match Scala's Int overflow —
    // consensus-critical for boxes whose serialized length exceeds the
    // i32 wrap point (~1,718 bytes at the default factor 1,250,000).
    let storage_fee =
        crate::storage_rent::compute_storage_fee(box_bytes_len, params.storage_fee_factor);

    // If box value doesn't cover the fee, the entire box is consumed.
    // Any output is acceptable in this case.
    let storage_fee_not_covered = (input_box.candidate.value as i64) - (storage_fee as i64) <= 0;
    if storage_fee_not_covered {
        return true;
    }

    // Otherwise the output must preserve the box's properties:
    let correct_creation_height = output.creation_height == current_height;
    let correct_value =
        output.value as i64 >= (input_box.candidate.value as i64) - (storage_fee as i64);

    // All registers except R0 (value) and R3 (creation height/reference) must match.
    // R0 and R3 are not in additionalRegisters (they're value and creationHeight fields).
    // R1 (script/ergoTree) and R2 (tokens) are checked via ergoTree and tokens fields.
    let correct_script = output.ergo_tree_bytes() == input_box.candidate.ergo_tree_bytes();
    let correct_tokens = output.tokens == input_box.candidate.tokens;
    let correct_registers = output.additional_registers == input_box.candidate.additional_registers;

    correct_creation_height
        && correct_value
        && correct_script
        && correct_tokens
        && correct_registers
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- storage rent: check_storage_rent boundary semantics -----
    //
    // Pin the per-output validation contract of
    // `check_storage_rent` against Scala's `checkExpiredBox` at
    // `ergo-wallet/.../ErgoInterpreter.scala`. The eligibility
    // threshold (`box_age >= storage_period`) is enforced at the
    // call site in `validate_scripts`; these tests focus on the
    // output-preservation contract given that eligibility passed.

    use crate::context::ProtocolParams;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate as Cand};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_ser::token::Token;

    // ----- helpers -----

    fn simple_tree() -> ErgoTree {
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

    fn alt_tree() -> ErgoTree {
        // Distinct from `simple_tree()` by `version` so the
        // serialized bytes differ — exercises the "script
        // changed" rejection path.
        ErgoTree {
            version: 1,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    fn empty_regs() -> AdditionalRegisters {
        AdditionalRegisters::empty()
    }

    fn regs_with_r4(byte_val: i8) -> AdditionalRegisters {
        AdditionalRegisters {
            registers: vec![RegisterValue {
                tpe: SigmaType::SByte,
                value: SigmaValue::Byte(byte_val),
            }],
        }
    }

    fn make_input_box(
        value: u64,
        creation_height: u32,
        tree: ErgoTree,
        tokens: Vec<Token>,
        regs: AdditionalRegisters,
    ) -> ErgoBox {
        let candidate = Cand::new(value, tree, creation_height, tokens, regs).unwrap();
        ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([0xAA; 32]),
            index: 0,
        }
    }

    fn make_output(
        value: u64,
        creation_height: u32,
        tree: ErgoTree,
        tokens: Vec<Token>,
        regs: AdditionalRegisters,
    ) -> Cand {
        Cand::new(value, tree, creation_height, tokens, regs).unwrap()
    }

    fn ctx_ext_with_output_idx(idx: i16) -> ContextExtension {
        let mut ext = ContextExtension::empty();
        ext.values.insert(
            STORAGE_INDEX_VAR_ID,
            (SigmaType::SShort, SigmaValue::Short(idx)),
        );
        ext
    }

    fn make_tx_with_one_input_and_outputs(outputs: Vec<Cand>) -> Transaction {
        Transaction {
            inputs: vec![Input {
                box_id: Digest32::from_bytes([1; 32]),
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: outputs,
        }
    }

    fn params_with_factor(factor: i32) -> ProtocolParams {
        let mut p = ProtocolParams::mainnet_default();
        p.storage_fee_factor = factor;
        p
    }

    // ----- happy path -----

    #[test]
    fn fee_not_covered_accepts_any_output() {
        // Tiny-value box can't pay the rent → entire box is
        // consumed; ANY output is acceptable. Pins the
        // Scala `storageFeeNotCovered ||` short-circuit.
        let in_box = make_input_box(1, 100, simple_tree(), vec![], empty_regs());
        // Wildly different output: alt tree, different value,
        // wrong creation height, etc. Must still pass because
        // fee > input value.
        let out = make_output(0, 999, alt_tree(), vec![], regs_with_r4(7));
        let tx = make_tx_with_one_input_and_outputs(vec![out]);
        let ext = ctx_ext_with_output_idx(0);
        let p = params_with_factor(1_250_000);

        assert!(
            check_storage_rent(&in_box, &ext, &tx, 200, &p),
            "fee-not-covered branch must accept any output",
        );
    }

    #[test]
    fn fee_covered_preserved_output_accepts() {
        // Large-value box: input.value ≫ fee. Output must
        // preserve script/tokens/registers AND have
        // creation_height == current_height AND
        // value ≥ input.value - fee.
        let in_value: u64 = 10_000_000_000;
        let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
        let current_height = 200;
        // fee = factor * box_bytes_len (i32 wrap). Compute via
        // the helper so we don't drift from the production
        // formula.
        let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
            .unwrap()
            .len() as i32;
        let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
        let preserved = make_output(
            (in_value as i64 - fee) as u64,
            current_height,
            simple_tree(),
            vec![],
            empty_regs(),
        );
        let tx = make_tx_with_one_input_and_outputs(vec![preserved]);
        let ext = ctx_ext_with_output_idx(0);
        let p = params_with_factor(1_250_000);

        assert!(check_storage_rent(&in_box, &ext, &tx, current_height, &p));
    }

    // ----- per-property rejection paths -----

    #[test]
    fn wrong_creation_height_rejects() {
        let in_value: u64 = 10_000_000_000;
        let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
        let current_height = 200;
        let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
            .unwrap()
            .len() as i32;
        let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
        // Output creation_height = current_height - 1 (one block off).
        let bad = make_output(
            (in_value as i64 - fee) as u64,
            current_height - 1,
            simple_tree(),
            vec![],
            empty_regs(),
        );
        let tx = make_tx_with_one_input_and_outputs(vec![bad]);
        let ext = ctx_ext_with_output_idx(0);
        let p = params_with_factor(1_250_000);

        assert!(
            !check_storage_rent(&in_box, &ext, &tx, current_height, &p),
            "creation_height != current_height must reject",
        );
    }

    #[test]
    fn insufficient_output_value_rejects() {
        let in_value: u64 = 10_000_000_000;
        let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
        let current_height = 200;
        let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
            .unwrap()
            .len() as i32;
        let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
        // One nanoErg below the required floor.
        let short = make_output(
            ((in_value as i64 - fee) - 1) as u64,
            current_height,
            simple_tree(),
            vec![],
            empty_regs(),
        );
        let tx = make_tx_with_one_input_and_outputs(vec![short]);
        let ext = ctx_ext_with_output_idx(0);
        let p = params_with_factor(1_250_000);

        assert!(
            !check_storage_rent(&in_box, &ext, &tx, current_height, &p),
            "output.value < input.value - fee must reject",
        );
    }

    #[test]
    fn changed_script_rejects() {
        let in_value: u64 = 10_000_000_000;
        let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
        let current_height = 200;
        let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
            .unwrap()
            .len() as i32;
        let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
        // Different ergo_tree (alt_tree() differs in version).
        let bad_tree = make_output(
            (in_value as i64 - fee) as u64,
            current_height,
            alt_tree(),
            vec![],
            empty_regs(),
        );
        let tx = make_tx_with_one_input_and_outputs(vec![bad_tree]);
        let ext = ctx_ext_with_output_idx(0);
        let p = params_with_factor(1_250_000);

        assert!(
            !check_storage_rent(&in_box, &ext, &tx, current_height, &p),
            "ergo_tree change must reject",
        );
    }

    #[test]
    fn changed_tokens_rejects() {
        // Token-preservation branch: output must carry the same
        // `tokens` vector as the input box. Adding a token to the
        // output → reject.
        let in_value: u64 = 10_000_000_000;
        let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
        let current_height = 200;
        let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
            .unwrap()
            .len() as i32;
        let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
        // Input has zero tokens; output adds one.
        let extra_token = Token {
            token_id: Digest32::from_bytes([0xAB; 32]),
            amount: 1,
        };
        let bad_tokens = make_output(
            (in_value as i64 - fee) as u64,
            current_height,
            simple_tree(),
            vec![extra_token],
            empty_regs(),
        );
        let tx = make_tx_with_one_input_and_outputs(vec![bad_tokens]);
        let ext = ctx_ext_with_output_idx(0);
        let p = params_with_factor(1_250_000);

        assert!(
            !check_storage_rent(&in_box, &ext, &tx, current_height, &p),
            "tokens change must reject",
        );
    }

    #[test]
    fn changed_registers_rejects() {
        let in_value: u64 = 10_000_000_000;
        let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
        let current_height = 200;
        let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
            .unwrap()
            .len() as i32;
        let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
        // Output adds an R4 register; input has none.
        let bad_regs = make_output(
            (in_value as i64 - fee) as u64,
            current_height,
            simple_tree(),
            vec![],
            regs_with_r4(42),
        );
        let tx = make_tx_with_one_input_and_outputs(vec![bad_regs]);
        let ext = ctx_ext_with_output_idx(0);
        let p = params_with_factor(1_250_000);

        assert!(
            !check_storage_rent(&in_box, &ext, &tx, current_height, &p),
            "additional_registers change must reject",
        );
    }

    // ----- context-extension edge cases -----

    #[test]
    fn missing_output_index_in_extension_rejects() {
        let in_box = make_input_box(1_000_000_000, 100, simple_tree(), vec![], empty_regs());
        let tx = make_tx_with_one_input_and_outputs(vec![make_output(
            1,
            200,
            simple_tree(),
            vec![],
            empty_regs(),
        )]);
        // ContextExtension is empty — no entry at var 127.
        let ext = ContextExtension::empty();
        let p = params_with_factor(1_250_000);

        assert!(
            !check_storage_rent(&in_box, &ext, &tx, 200, &p),
            "missing output-index var must reject (no fallback)",
        );
    }

    #[test]
    fn output_index_out_of_bounds_rejects() {
        let in_box = make_input_box(1_000_000_000, 100, simple_tree(), vec![], empty_regs());
        // Tx has 1 output; extension references index 5.
        let tx = make_tx_with_one_input_and_outputs(vec![make_output(
            1,
            200,
            simple_tree(),
            vec![],
            empty_regs(),
        )]);
        let ext = ctx_ext_with_output_idx(5);
        let p = params_with_factor(1_250_000);

        assert!(
            !check_storage_rent(&in_box, &ext, &tx, 200, &p),
            "out-of-bounds output index must reject",
        );
    }

    // ----- 4-year-boundary eligibility edges -----

    #[test]
    fn eligibility_just_below_storage_period_rejected() {
        // `box_age == storage_period - 1` is one block short of
        // the 4-year mark. Eligibility fails; normal script
        // verification path applies.
        assert!(
            !is_storage_rent_eligible(1_051_199, 1_051_200, true, true),
            "one block below threshold must fail eligibility",
        );
    }

    #[test]
    fn eligibility_at_storage_period_accepted() {
        // Boundary case: Scala uses `>=`, so `box_age ==
        // storage_period` (1_051_200) is sufficient.
        assert!(
            is_storage_rent_eligible(1_051_200, 1_051_200, true, true),
            "at-threshold box_age must enter rent path",
        );
    }

    #[test]
    fn eligibility_well_past_storage_period_accepted() {
        // Multiple consecutive periods are all eligible — Scala
        // doesn't reset eligibility per period. 8 years
        // (2 × storage_period) still triggers rent.
        assert!(is_storage_rent_eligible(
            2 * 1_051_200,
            1_051_200,
            true,
            true,
        ));
        // 16 years
        assert!(is_storage_rent_eligible(
            4 * 1_051_200,
            1_051_200,
            true,
            true,
        ));
    }

    #[test]
    fn eligibility_requires_empty_proof() {
        // Eligible by age + var, but spending proof non-empty
        // — must NOT enter rent path. Scala's
        // `proof.length == 0` predicate.
        assert!(
            !is_storage_rent_eligible(2_000_000, 1_051_200, false, true),
            "non-empty proof must disable rent path",
        );
    }

    #[test]
    fn eligibility_requires_storage_var() {
        // Eligible by age + empty proof, but no var #127 in
        // context extension — must NOT enter rent path.
        assert!(
            !is_storage_rent_eligible(2_000_000, 1_051_200, true, false),
            "missing storage-index var must disable rent path",
        );
    }

    #[test]
    fn eligibility_fresh_box_rejected() {
        // box_age == 0 (just created): nowhere near eligibility.
        assert!(!is_storage_rent_eligible(0, 1_051_200, true, true));
    }

    #[test]
    fn eligibility_zero_storage_period_degenerate_accepts_any_age() {
        // Defensive corner: a testnet/dev config with
        // storage_period=0 makes EVERY non-fresh box eligible.
        // Pin this so a future refactor doesn't accidentally
        // hard-code mainnet's 1_051_200 into the predicate.
        assert!(is_storage_rent_eligible(0, 0, true, true));
        assert!(is_storage_rent_eligible(1, 0, true, true));
    }

    #[test]
    fn output_index_int_variant_also_accepted() {
        // Scala accepts both Short and Int as the variable
        // type. Our code path matches: ensure an Int-typed
        // entry resolves the same output as a Short-typed one.
        let in_value: u64 = 10_000_000_000;
        let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
        let current_height = 200;
        let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
            .unwrap()
            .len() as i32;
        let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
        let preserved = make_output(
            (in_value as i64 - fee) as u64,
            current_height,
            simple_tree(),
            vec![],
            empty_regs(),
        );
        let tx = make_tx_with_one_input_and_outputs(vec![preserved]);
        let mut ext = ContextExtension::empty();
        ext.values
            .insert(STORAGE_INDEX_VAR_ID, (SigmaType::SInt, SigmaValue::Int(0)));
        let p = params_with_factor(1_250_000);

        assert!(check_storage_rent(&in_box, &ext, &tx, current_height, &p));
    }
}
