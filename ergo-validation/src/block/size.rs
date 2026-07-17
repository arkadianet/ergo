use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};

use crate::error::ValidationError;

use super::error::BlockValidationError;

/// Scala `bsBlockTransactionsSize` (rule 306) — caps the
/// serialized `BlockTransactions` section at
/// `params.max_block_size`. Matches Scala's
/// `fb.blockTransactions.size <= currentParameters.maxBlockSize`
/// at `ErgoStateContext.appendFullBlock:308-310`.
///
/// Re-serializes via `write_block_transactions_with_version`
/// because Scala's `.size` is the cached serialized length (or
/// `bytes.length` when uncached). The cost is O(N) of the block,
/// same as the transactions-root walk that already ran upstream,
/// so the only adversarial concern is that this runs AFTER
/// `transactions_root` confirms the bytes match the header
/// commitment — the "structural check after cryptographic binding"
/// ordering keeps an unbound block from forcing the reserialize.
pub(crate) fn check_block_transactions_size(
    block_transactions: &BlockTransactions,
    block_version: u8,
    max_block_size: u32,
) -> Result<(), BlockValidationError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    write_block_transactions_with_version(&mut w, block_transactions, block_version).map_err(
        |e| BlockValidationError::Transaction {
            index: 0,
            error: ValidationError::Deserialization(format!("block_transactions reserialize: {e}")),
        },
    )?;
    let size = w.result().len();
    if size > max_block_size as usize {
        return Err(BlockValidationError::BlockTransactionsTooLarge {
            size,
            max: max_block_size,
        });
    }
    Ok(())
}

/// Rule 306 (`bsBlockTransactionsSize`) tests.
#[cfg(test)]
mod block_transactions_size_tests {
    use super::*;
    use crate::context::ProtocolParams;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_ser::transaction::Transaction;

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

    fn make_input(fill: u8) -> Input {
        Input {
            box_id: Digest32::from_bytes([fill; 32]),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }
    }

    fn make_candidate(creation_height: u32) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            1_000_000_000_000,
            simple_tree(),
            creation_height,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn one_input_tx(input_fill: u8) -> Transaction {
        Transaction {
            inputs: vec![make_input(input_fill)],
            data_inputs: vec![],
            output_candidates: vec![make_candidate(100)],
        }
    }

    fn make_block_txs(n: usize) -> BlockTransactions {
        // Distinct `input_fill` per tx keeps tx ids distinct without
        // needing per-tx tree variation.
        let transactions: Vec<Transaction> =
            (0..n).map(|i| one_input_tx((i & 0xff) as u8)).collect();
        BlockTransactions {
            header_id: ModifierId::from_bytes([0xAA; 32]),
            transactions,
        }
    }

    fn serialized_size(bt: &BlockTransactions, version: u8) -> usize {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        write_block_transactions_with_version(&mut w, bt, version).unwrap();
        w.result().len()
    }

    #[test]
    fn block_transactions_under_cap_passes() {
        // A single-tx block is far under any reasonable cap.
        let bt = make_block_txs(1);
        let size = serialized_size(&bt, 1);
        // Use mainnet default 524 KiB cap — single tx is well under.
        let max = ProtocolParams::mainnet_default().max_block_size;
        assert!(
            size < max as usize,
            "fixture size {size} must be under {max}"
        );
        check_block_transactions_size(&bt, 1, max).unwrap();
    }

    #[test]
    fn block_transactions_at_cap_passes() {
        // Cap = exact serialized size: the inequality is `<=`,
        // so equality must pass.
        let bt = make_block_txs(5);
        let size = serialized_size(&bt, 1);
        check_block_transactions_size(&bt, 1, size as u32).unwrap();
    }

    #[test]
    fn block_transactions_one_byte_over_cap_rejects() {
        // Set cap to actual_size - 1 and assert reject.
        let bt = make_block_txs(5);
        let size = serialized_size(&bt, 1);
        let cap = (size - 1) as u32;
        let err = check_block_transactions_size(&bt, 1, cap).unwrap_err();
        match err {
            BlockValidationError::BlockTransactionsTooLarge { size: s, max: m } => {
                assert_eq!(s, size);
                assert_eq!(m, cap);
            }
            other => panic!("expected BlockTransactionsTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn block_transactions_far_over_cap_rejects() {
        // Multi-tx block with an artificially tiny cap — exercises
        // the "obvious overlimit" path without needing huge fixtures.
        let bt = make_block_txs(10);
        let err = check_block_transactions_size(&bt, 1, 16).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::BlockTransactionsTooLarge { .. }
        ));
    }

    #[test]
    fn block_transactions_size_version_aware() {
        // v1 and v2+ formats produce different byte lengths
        // (v2+ adds the version marker + per-section framing).
        // The check must measure with the supplied block_version,
        // not assume v1.
        let bt = make_block_txs(3);
        let v1_size = serialized_size(&bt, 1);
        let v2_size = serialized_size(&bt, 2);
        assert!(
            v2_size != v1_size,
            "v1 and v2 fixtures must produce different sizes \
             (got v1={v1_size}, v2={v2_size}) — otherwise this test \
             doesn't actually exercise version-awareness",
        );
        // Cap = v1 size, but pass version=2 → the rule must measure
        // v2 and reject because v2 size > v1 size (or accept if v2
        // happens to be smaller — for our 3-tx fixture v2 is larger).
        let cap_at_v1 = v1_size as u32;
        let result = check_block_transactions_size(&bt, 2, cap_at_v1);
        if v2_size > v1_size {
            assert!(matches!(
                result,
                Err(BlockValidationError::BlockTransactionsTooLarge { .. })
            ));
        } else {
            assert!(result.is_ok());
        }
    }
}
