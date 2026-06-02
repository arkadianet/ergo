use std::collections::HashSet;

use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{write_ergo_box_candidate, ErgoBoxCandidate};
use ergo_ser::transaction::Transaction;

use crate::context::ProtocolParams;
use crate::error::ValidationError;

/// Scala `Short.MaxValue` — validator-level cap on input / data-input /
/// output count for rules 102 / 103 / 104. Distinct from the wire-
/// codec cap of `u16::MAX = 65_535` in `ergo-ser/src/transaction.rs`:
/// Scala uses `Short` (signed i16) for the count field at the
/// validation layer even though the wire format encodes as unsigned
/// `u16`, so any tx with count in `32_768..=65_535` parses fine but
/// fails Scala's validator with the matching rule. Our validator
/// enforces the tighter cap to keep that boundary.
pub const SCALA_SHORT_MAX: usize = i16::MAX as usize;

/// Sigma-state `MaxPropositionBytes` — Scala constant
/// `sigma.data.SigmaConstants.MaxPropositionBytes` in
/// `reference/sigmastate-interpreter/.../SigmaConstants.scala:40`
/// (`4096`). Rule 121 (`txBoxPropositionSize`) caps an output's
/// `propositionBytes` length at this value. Independent of
/// `max_box_size` (the per-output payload cap) — a box can be well
/// under the box-size cap while still violating the proposition cap
/// via an oversized `ergo_tree`.
pub const MAX_PROPOSITION_BYTES: usize = 4096;

/// Stateless structural validation of a parsed transaction.
/// No UTXO set or chain state needed.
pub fn validate_structural(
    tx: &Transaction,
    params: &ProtocolParams,
) -> Result<(), ValidationError> {
    check_has_inputs(tx)?;
    check_collection_caps(tx)?;
    check_no_duplicate_inputs(tx)?;
    // Note: duplicate data inputs are allowed (read-only references, matches Scala)
    for (i, out) in tx.output_candidates.iter().enumerate() {
        check_output_box(i, out, params)?;
    }
    Ok(())
}

fn check_has_inputs(tx: &Transaction) -> Result<(), ValidationError> {
    if tx.inputs.is_empty() {
        return Err(ValidationError::NoInputs);
    }
    Ok(())
}

/// Rules 102 / 103 / 104 — Scala validator caps the count of each
/// transaction collection at `Short.MaxValue`. The wire codec
/// accepts up to `u16::MAX`, so this validator-side check is the
/// only thing that catches a tx with `32_768..=65_535` inputs (or
/// data inputs or outputs) before the per-input / per-output work
/// would otherwise run.
fn check_collection_caps(tx: &Transaction) -> Result<(), ValidationError> {
    if tx.inputs.len() > SCALA_SHORT_MAX {
        return Err(ValidationError::TooManyInputs {
            count: tx.inputs.len(),
            max: SCALA_SHORT_MAX,
        });
    }
    if tx.data_inputs.len() > SCALA_SHORT_MAX {
        return Err(ValidationError::TooManyDataInputs {
            count: tx.data_inputs.len(),
            max: SCALA_SHORT_MAX,
        });
    }
    if tx.output_candidates.len() > SCALA_SHORT_MAX {
        return Err(ValidationError::TooManyOutputs {
            count: tx.output_candidates.len(),
            max: SCALA_SHORT_MAX,
        });
    }
    Ok(())
}

fn check_no_duplicate_inputs(tx: &Transaction) -> Result<(), ValidationError> {
    let mut seen = HashSet::new();
    for (i, input) in tx.inputs.iter().enumerate() {
        if !seen.insert(input.box_id) {
            return Err(ValidationError::DuplicateInput { index: i });
        }
    }
    Ok(())
}

fn check_output_box(
    index: usize,
    out: &ErgoBoxCandidate,
    params: &ProtocolParams,
) -> Result<(), ValidationError> {
    let box_size = serialized_box_size(out, index as u16)?;

    if box_size > params.max_box_size as usize {
        return Err(ValidationError::BoxTooLarge {
            index,
            size: box_size,
            max: params.max_box_size,
        });
    }

    // Scala's `out.propositionBytes` is the **original** bytes captured
    // at deserialization time, not a re-serialization of the parsed
    // tree. The two diverge for soft-fork trees: a tree with
    // version > `MAX_SUPPORTED_TREE_VERSION` is wrapped into the
    // synthetic `unparsed_soft_fork_tree` by `read_ergo_tree`, which
    // re-serializes to ~10 bytes while the original wire bytes may be
    // arbitrarily large. Reading `ergo_tree_bytes()` matches Scala's
    // cached `propositionBytes` field — works for both fresh-construct
    // (where `ErgoBoxCandidate::new` cached the re-serialized form)
    // and parsed-from-wire (where the verbatim bytes were captured by
    // `read_box_tail`).
    let prop_size = out.ergo_tree_bytes().len();
    if prop_size > MAX_PROPOSITION_BYTES {
        return Err(ValidationError::PropositionTooLarge {
            index,
            size: prop_size,
            max: MAX_PROPOSITION_BYTES,
        });
    }

    // Min value: value >= serialized_box_size * min_value_per_byte
    let min_value = (box_size as u64).saturating_mul(params.min_value_per_byte);
    if out.value < min_value {
        return Err(ValidationError::OutputValueTooLow {
            index,
            value: out.value,
            min: min_value,
        });
    }

    if out.tokens.len() > params.max_tokens_per_box as usize {
        return Err(ValidationError::TooManyTokens {
            index,
            count: out.tokens.len(),
            max: params.max_tokens_per_box,
        });
    }

    Ok(())
}

/// Compute the serialized size of a box for min-value calculation.
///
/// Scala uses `box.bytes.length` which includes transaction_id (32 bytes)
/// and the VLQ-encoded output index. We serialize the candidate and add
/// 32 + vlq_size(index) to match.
fn serialized_box_size(out: &ErgoBoxCandidate, index: u16) -> Result<usize, ValidationError> {
    let mut w = VlqWriter::new();
    write_ergo_box_candidate(&mut w, out)
        .map_err(|e| ValidationError::Deserialization(e.to_string()))?;
    let mut idx_w = VlqWriter::new();
    idx_w.put_u16(index);
    Ok(w.result().len() + 32 + idx_w.result().len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{CollValue, SigmaValue};

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

    fn make_candidate(value: u64) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            value,
            simple_tree(),
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn make_input(fill: u8) -> Input {
        Input {
            box_id: Digest32::from_bytes([fill; 32]),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }
    }

    fn make_tx(inputs: Vec<Input>, outputs: Vec<ErgoBoxCandidate>) -> Transaction {
        Transaction {
            inputs,
            data_inputs: vec![],
            output_candidates: outputs,
        }
    }

    #[test]
    fn no_inputs_rejected() {
        let tx = make_tx(vec![], vec![make_candidate(1_000_000)]);
        let params = ProtocolParams::mainnet_default();
        let err = validate_structural(&tx, &params).unwrap_err();
        assert!(matches!(err, ValidationError::NoInputs));
    }

    #[test]
    fn duplicate_input_rejected() {
        let tx = make_tx(
            vec![make_input(1), make_input(1)],
            vec![make_candidate(1_000_000)],
        );
        let params = ProtocolParams::mainnet_default();
        let err = validate_structural(&tx, &params).unwrap_err();
        assert!(matches!(err, ValidationError::DuplicateInput { index: 1 }));
    }

    #[test]
    fn output_value_too_low_rejected() {
        // A minimal box is ~60 candidate bytes + 34 = ~94 bytes
        // min value = 94 * 360 = 33_840 nanoErg
        let tx = make_tx(
            vec![make_input(1)],
            vec![make_candidate(1)], // 1 nanoErg is too low
        );
        let params = ProtocolParams::mainnet_default();
        let err = validate_structural(&tx, &params).unwrap_err();
        assert!(matches!(err, ValidationError::OutputValueTooLow { .. }));
    }

    #[test]
    fn valid_structural_passes() {
        let tx = make_tx(
            vec![make_input(1), make_input(2)],
            vec![make_candidate(1_000_000_000)],
        );
        let params = ProtocolParams::mainnet_default();
        validate_structural(&tx, &params).unwrap();
    }

    // ----- Collection-count caps (Scala rules 102 / 103 / 104) -----

    /// Helper: build a tx with `n_in` inputs / `n_data` data inputs /
    /// `n_out` output candidates. Inputs and data inputs share the
    /// same `box_id` so the duplicate-input check would fire on them
    /// at large `n_in` — that's why the boundary tests invoke
    /// `check_collection_caps` directly instead of `validate_structural`.
    fn make_tx_with_counts(n_in: usize, n_data: usize, n_out: usize) -> Transaction {
        let inputs: Vec<Input> = std::iter::repeat_with(|| make_input(1))
            .take(n_in)
            .collect();
        let data_inputs = std::iter::repeat_with(|| ergo_ser::input::DataInput {
            box_id: Digest32::from_bytes([2; 32]),
        })
        .take(n_data)
        .collect();
        let outputs: Vec<ErgoBoxCandidate> =
            std::iter::repeat_with(|| make_candidate(1_000_000_000))
                .take(n_out)
                .collect();
        Transaction {
            inputs,
            data_inputs,
            output_candidates: outputs,
        }
    }

    #[test]
    fn inputs_at_scala_short_max_accepted() {
        // SCALA_SHORT_MAX = i16::MAX = 32_767. The cap is `>`, not `>=`,
        // so a count of exactly the cap must pass.
        let tx = make_tx_with_counts(SCALA_SHORT_MAX, 0, 1);
        check_collection_caps(&tx).unwrap();
    }

    #[test]
    fn inputs_one_over_scala_short_max_rejected() {
        let n = SCALA_SHORT_MAX + 1;
        let tx = make_tx_with_counts(n, 0, 1);
        let err = check_collection_caps(&tx).unwrap_err();
        match err {
            ValidationError::TooManyInputs { count, max } => {
                assert_eq!(count, n);
                assert_eq!(max, SCALA_SHORT_MAX);
                assert_eq!(max, i16::MAX as usize);
            }
            other => panic!("expected TooManyInputs, got {other:?}"),
        }
    }

    #[test]
    fn data_inputs_one_over_scala_short_max_rejected() {
        let n = SCALA_SHORT_MAX + 1;
        let tx = make_tx_with_counts(1, n, 1);
        let err = check_collection_caps(&tx).unwrap_err();
        match err {
            ValidationError::TooManyDataInputs { count, max } => {
                assert_eq!(count, n);
                assert_eq!(max, SCALA_SHORT_MAX);
            }
            other => panic!("expected TooManyDataInputs, got {other:?}"),
        }
    }

    #[test]
    fn outputs_one_over_scala_short_max_rejected() {
        let n = SCALA_SHORT_MAX + 1;
        let tx = make_tx_with_counts(1, 0, n);
        let err = check_collection_caps(&tx).unwrap_err();
        match err {
            ValidationError::TooManyOutputs { count, max } => {
                assert_eq!(count, n);
                assert_eq!(max, SCALA_SHORT_MAX);
            }
            other => panic!("expected TooManyOutputs, got {other:?}"),
        }
    }

    #[test]
    fn collection_cap_fires_before_duplicate_check() {
        // A tx with 32_768 duplicate inputs (would also fail
        // duplicate-input) MUST surface as `TooManyInputs` because
        // the cap check runs first in `validate_structural`. A
        // future ordering swap would change which Scala rule the
        // operator log cites.
        let tx = make_tx_with_counts(SCALA_SHORT_MAX + 1, 0, 1);
        let params = ProtocolParams::mainnet_default();
        let err = validate_structural(&tx, &params).unwrap_err();
        assert!(
            matches!(err, ValidationError::TooManyInputs { .. }),
            "cap must fire before duplicate-input check, got {err:?}",
        );
    }

    #[test]
    fn ordinary_tx_under_caps_passes() {
        // Sanity: a 1-in / 0-data / 1-out tx (typical mainnet shape)
        // must pass cap check unconditionally.
        let tx = make_tx_with_counts(1, 0, 1);
        check_collection_caps(&tx).unwrap();
    }

    // ----- Box-proposition-size cap (Scala rule 121) -----

    /// Build a tree whose `propositionBytes` is dominated by a single
    /// `Coll[Byte]` constant of the requested length. The exact
    /// serialized size includes a small fixed overhead (header +
    /// size-field + opcode bytes); use `serialized_proposition_size`
    /// to measure the result rather than assuming a 1:1 mapping.
    fn tree_with_byte_payload(payload_len: usize) -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                val: SigmaValue::Coll(CollValue::Bytes(vec![0u8; payload_len])),
            },
        }
    }

    /// Mainnet params with `max_box_size` relaxed to `u32::MAX`. In
    /// production both `MaxBoxSize` and `MaxPropositionBytes` are
    /// 4 KiB, so rule 120 (box-size) shadows rule 121 (proposition-
    /// size) for any tree large enough to violate 121 — the wrapping
    /// box is always larger. Scala has the same numeric collision but
    /// keeps both rules as separate registry entries; we mirror that.
    /// These tests have to relax `max_box_size` so rule 121 can fire
    /// in isolation, which is the only way to actually exercise the
    /// `PropositionTooLarge` variant under current params.
    fn params_with_box_size_unbounded() -> ProtocolParams {
        let mut p = ProtocolParams::mainnet_default();
        p.max_box_size = u32::MAX;
        p
    }

    #[test]
    fn max_proposition_bytes_pins_at_4096() {
        // Pin the Scala constant locally so a future drift in
        // SigmaConstants.MaxPropositionBytes can't silently retune
        // our cap.
        assert_eq!(MAX_PROPOSITION_BYTES, 4096);
    }

    #[test]
    fn simple_tree_proposition_well_under_cap_passes() {
        // The default `simple_tree` (a one-constant Boolean tree)
        // serializes well under 4 KiB; an ordinary tx using it must
        // pass the proposition-size check without rejection.
        let tx = make_tx(vec![make_input(1)], vec![make_candidate(1_000_000_000)]);
        let params = ProtocolParams::mainnet_default();
        validate_structural(&tx, &params).unwrap();
    }

    #[test]
    fn proposition_far_over_cap_rejected() {
        // 5_000-byte byte-array payload — `ErgoBoxCandidate::new`
        // caches the re-serialized form into `ergo_tree_bytes`, which
        // is what rule 121 measures. Box-size cap relaxed so rule 121
        // isn't shadowed by rule 120.
        let tree = tree_with_byte_payload(5_000);
        let candidate = ErgoBoxCandidate::new(
            1_000_000_000_000,
            tree,
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        let prop_size = candidate.ergo_tree_bytes().len();
        assert!(
            prop_size > MAX_PROPOSITION_BYTES,
            "test setup invariant: payload must be over cap, got {prop_size}",
        );

        let tx = make_tx(vec![make_input(1)], vec![candidate]);
        let params = params_with_box_size_unbounded();
        let err = validate_structural(&tx, &params).unwrap_err();
        match err {
            ValidationError::PropositionTooLarge { index, size, max } => {
                assert_eq!(index, 0);
                assert_eq!(size, prop_size);
                assert_eq!(max, MAX_PROPOSITION_BYTES);
            }
            other => panic!("expected PropositionTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn proposition_boundary_acceptance_flips_at_cap() {
        // Sweep payload lengths around the cap and assert the
        // acceptance boundary tracks `ergo_tree_bytes().len()`
        // exactly — every candidate whose cached tree bytes are
        // ≤ 4_096 accepts, every one > 4_096 rejects. Box-size cap
        // relaxed so rule 120 doesn't shadow rule 121.
        let params = params_with_box_size_unbounded();
        for payload_len in 4_080..=4_100 {
            let tree = tree_with_byte_payload(payload_len);
            let candidate = ErgoBoxCandidate::new(
                1_000_000_000_000,
                tree,
                100,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap();
            let prop_size = candidate.ergo_tree_bytes().len();

            let tx = make_tx(vec![make_input(1)], vec![candidate]);
            let result = validate_structural(&tx, &params);

            if prop_size <= MAX_PROPOSITION_BYTES {
                assert!(
                    result.is_ok(),
                    "payload {payload_len} (prop {prop_size}) should accept, got {result:?}",
                );
            } else {
                match result {
                    Err(ValidationError::PropositionTooLarge { size, max, .. }) => {
                        assert_eq!(size, prop_size);
                        assert_eq!(max, MAX_PROPOSITION_BYTES);
                    }
                    other => panic!(
                        "payload {payload_len} (prop {prop_size}) should reject PropositionTooLarge, got {other:?}",
                    ),
                }
            }
        }
    }

    #[test]
    fn soft_fork_oversized_proposition_rejected() {
        // Soft-fork divergence scenario: a tree with version > our
        // `MAX_SUPPORTED_TREE_VERSION` arrives over the wire with
        // 5_000 bytes of body. `read_ergo_tree` wraps it into the
        // synthetic `unparsed_soft_fork_tree` (which re-serializes to
        // ~10 bytes), but `read_box_tail` preserves the original
        // verbatim bytes on the candidate. Rule 121 must measure the
        // verbatim bytes (= Scala's cached `propositionBytes`), not
        // the synthetic re-serialization — otherwise an adversary
        // could ship a 5 KB unparsed-tree box that our validator
        // would silently accept while Scala rejects.
        //
        // We can't reach the real soft-fork construction path from
        // here (it's wire-deserializer-internal). `from_trusted_raw_parts`
        // is the byte-exact mock: pair a tiny placeholder tree with
        // large verbatim bytes the same way `read_box_tail` would.
        let placeholder_tree = simple_tree();
        let oversize_bytes = vec![0u8; 5_000];
        let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
            1_000_000_000_000,
            placeholder_tree,
            oversize_bytes.clone(),
            100,
            vec![],
            AdditionalRegisters::empty(),
            vec![0],
        );
        assert_eq!(candidate.ergo_tree_bytes().len(), 5_000);

        let tx = make_tx(vec![make_input(1)], vec![candidate]);
        let params = params_with_box_size_unbounded();
        let err = validate_structural(&tx, &params).unwrap_err();
        match err {
            ValidationError::PropositionTooLarge { index, size, max } => {
                assert_eq!(index, 0);
                assert_eq!(size, 5_000);
                assert_eq!(max, MAX_PROPOSITION_BYTES);
            }
            other => panic!("expected PropositionTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn box_size_cap_shadows_proposition_cap_in_mainnet_params() {
        // Mainnet config invariant: rule 120 (box-size 4_096) and
        // rule 121 (proposition-size 4_096) have the same cap, so an
        // oversized tree always trips 120 first because the box
        // wraps the proposition with at least ~32 + 2 + values + tokens
        // bytes of overhead. This pin breaks if the two caps ever
        // diverge in `ProtocolParams::mainnet_default`, which would
        // mean rule 121 starts firing in production paths.
        let tree = tree_with_byte_payload(5_000);
        let candidate = ErgoBoxCandidate::new(
            1_000_000_000_000,
            tree,
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        let tx = make_tx(vec![make_input(1)], vec![candidate]);
        let params = ProtocolParams::mainnet_default();

        let err = validate_structural(&tx, &params).unwrap_err();
        assert!(
            matches!(err, ValidationError::BoxTooLarge { .. }),
            "expected box-size cap to fire first under mainnet params, got {err:?}",
        );
    }
}
