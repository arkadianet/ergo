//! External Scala verdict/cost/canonical-byte evidence for propositions whose
//! logical size grows exponentially while stored evaluator values remain shared.

use ergo_primitives::{
    cost::{CostAccumulator, JitCost},
    reader::VlqReader,
    writer::VlqWriter,
};
use ergo_ser::{ergo_tree::read_ergo_tree, sigma_value::write_sigma_boolean};
use ergo_sigma::{
    evaluator::{reduce_expr_with_cost, EvalError, ReductionContext},
    reduce::{verify_spending_proof_with_context_and_cost, VerifySpendingError},
};
use sha2::{Digest, Sha256};

// ----- oracle parity -----

#[test]
fn shared_fold_matches_scala_bytes_size_cost_and_verification() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/scala/sigma_shared_growth.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let bytes = hex::decode(case["tree_hex"].as_str().unwrap()).unwrap();
        let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
        let tree = read_ergo_tree(&mut reader).unwrap();
        assert!(reader.is_empty());
        let mut ctx = ReductionContext::minimal(0, 0);
        ctx.ergo_tree_version = tree.version;
        let limit = JitCost::from_block_cost(case["limit_block"].as_u64().unwrap()).unwrap();
        let mut cost = CostAccumulator::new(limit);
        let prop = reduce_expr_with_cost(&tree.body, &ctx, &tree.constants, &mut cost).unwrap();
        assert_eq!(cost.total().value(), case["eval_jit"].as_u64().unwrap());
        assert_eq!(prop.size() as u64, case["sigma_size"].as_u64().unwrap());
        assert_eq!(
            ergo_sigma::crypto_cost::estimate_crypto_cost(&prop).value(),
            case["crypto_jit"].as_u64().unwrap()
        );
        let mut writer = VlqWriter::new();
        write_sigma_boolean(&mut writer, &prop).unwrap();
        let encoded = writer.result();
        assert_eq!(encoded.len() as u64, case["sigma_bytes"].as_u64().unwrap());
        assert_eq!(
            hex::encode(Sha256::digest(&encoded)),
            case["sigma_sha256"].as_str().unwrap()
        );

        let mut verify_cost = CostAccumulator::new(limit);
        let result =
            verify_spending_proof_with_context_and_cost(&tree, &[], &[], &ctx, &mut verify_cost);
        match case["verify_verdict"].as_str().unwrap() {
            "RejectProof" => {
                assert!(!result.unwrap());
                assert_eq!(
                    verify_cost.total().value() / 10,
                    case["verify_cost_block"].as_u64().unwrap()
                );
            }
            "RejectCost" => assert!(matches!(
                result,
                Err(VerifySpendingError::Eval(EvalError::CostExceeded(_)))
            )),
            other => panic!("unexpected external verdict {other}"),
        }
    }
}

#[test]
fn proof_traversal_matches_independently_generated_scala_proofs() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/scala/sigma_shared_growth.json"
    ))
    .unwrap();
    for case in fixture["proof_cases"].as_array().unwrap() {
        let bytes = hex::decode(case["tree_hex"].as_str().unwrap()).unwrap();
        let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
        let tree = read_ergo_tree(&mut reader).unwrap();
        let mut ctx = ReductionContext::minimal(0, 0);
        ctx.ergo_tree_version = tree.version;
        let mut cost = CostAccumulator::new(JitCost::from_jit(1_000_000));
        let prop = reduce_expr_with_cost(&tree.body, &ctx, &tree.constants, &mut cost).unwrap();
        let proof = hex::decode(case["proof_hex"].as_str().unwrap()).unwrap();
        let message = hex::decode(case["message_hex"].as_str().unwrap()).unwrap();
        for (bytes, message, field) in [
            (proof.as_slice(), message.as_slice(), "valid"),
            (proof.as_slice(), &[1][..], "wrong_message_valid"),
            (&proof[..23], message.as_slice(), "truncated_valid"),
        ] {
            let valid =
                ergo_sigma::verify::verify_sigma_proof(&prop, bytes, message).unwrap_or(false);
            assert_eq!(
                valid,
                case[field].as_bool().unwrap(),
                "{}: {field}",
                case["name"]
            );
        }
        for (len, expected) in case["prefix_valid"].as_array().unwrap().iter().enumerate() {
            let valid = ergo_sigma::verify::verify_sigma_proof(&prop, &proof[..len], &message)
                .unwrap_or(false);
            assert_eq!(
                valid,
                expected.as_bool().unwrap(),
                "{}: prefix {len}",
                case["name"]
            );
        }
        for (offset, expected) in case["flipped_byte_valid"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let mut changed = proof.clone();
            changed[offset] ^= 1;
            let valid =
                ergo_sigma::verify::verify_sigma_proof(&prop, &changed, &message).unwrap_or(false);
            assert_eq!(
                valid,
                expected.as_bool().unwrap(),
                "{}: changed byte {offset}",
                case["name"]
            );
        }
    }
}
