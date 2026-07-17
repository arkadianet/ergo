use ergo_primitives::digest::ModifierId;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::register::RegisterValue;
use ergo_sigma::evaluator::EvalBox;

use crate::error::ValidationError;

/// Convert a resolved ErgoBox to the evaluator's EvalBox format.
/// pub(crate) for test_helpers re-export; not part of the public API.
pub(crate) fn ergo_box_to_eval_box(b: &ErgoBox, index: usize) -> Result<EvalBox, ValidationError> {
    let id = b.box_id().map_err(|e| ValidationError::ScriptError {
        index,
        reason: format!("box_id computation failed: {e}"),
    })?;

    // ExtractBytes (0xC3) reads `EvalBox.raw_bytes` at script-eval time;
    // a silent fallback to empty bytes here would silently change script
    // semantics. Surface the write failure as a structured ScriptError.
    let raw_bytes = {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::ergo_box::write_ergo_box(&mut w, b).map_err(|e| {
            ValidationError::ScriptError {
                index,
                reason: format!("ErgoBox serialization for ExtractBytes failed: {e}"),
            }
        })?;
        w.result()
    };

    Ok(EvalBox {
        creation_height: b.candidate.creation_height,
        script_bytes: b.candidate.ergo_tree_bytes().to_vec(),
        value: b.candidate.value as i64,
        id: *id.as_bytes(),
        transaction_id: *b.transaction_id.as_bytes(),
        output_index: b.index,
        registers: copy_registers(&b.candidate.additional_registers),
        tokens: b
            .candidate
            .tokens
            .iter()
            .map(|t| (*t.token_id.as_bytes(), t.amount))
            .collect(),
        raw_bytes,
        register_bytes: b.candidate.register_bytes().to_vec(),
    })
}

/// Convert an output candidate to EvalBox with its real box ID.
/// pub(crate) for test_helpers re-export; not part of the public API.
pub(crate) fn candidate_to_eval_box(
    c: &ErgoBoxCandidate,
    tx_id: &ModifierId,
    index: u16,
) -> Result<EvalBox, ValidationError> {
    let temp_box = ErgoBox {
        candidate: c.clone(),
        transaction_id: *tx_id,
        index,
    };
    let id = temp_box
        .box_id()
        .map_err(|e| ValidationError::ScriptError {
            index: index as usize,
            reason: format!("output box_id computation failed: {e}"),
        })?;

    // See `ergo_box_to_eval_box`: ExtractBytes reads raw_bytes; failures
    // here would silently corrupt script semantics.
    let raw_bytes = {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::ergo_box::write_ergo_box(&mut w, &temp_box).map_err(|e| {
            ValidationError::ScriptError {
                index: index as usize,
                reason: format!("output ErgoBox serialization for ExtractBytes failed: {e}"),
            }
        })?;
        w.result()
    };

    Ok(EvalBox {
        creation_height: c.creation_height,
        script_bytes: c.ergo_tree_bytes().to_vec(),
        value: c.value as i64,
        id: *id.as_bytes(),
        transaction_id: *tx_id.as_bytes(),
        output_index: index,
        registers: copy_registers(&c.additional_registers),
        tokens: c
            .tokens
            .iter()
            .map(|t| (*t.token_id.as_bytes(), t.amount))
            .collect(),
        raw_bytes,
        register_bytes: c.register_bytes().to_vec(),
    })
}

/// Copy raw register data into the evaluator's lazy register slots.
/// Conversion to Value happens on demand in the evaluator via sigma_to_value.
fn copy_registers(regs: &ergo_ser::register::AdditionalRegisters) -> [Option<RegisterValue>; 6] {
    let mut result: [Option<RegisterValue>; 6] = [None, None, None, None, None, None];
    for (i, reg) in regs.registers.iter().enumerate() {
        if i < 6 {
            result[i] = Some(reg.clone());
        }
    }
    result
}
