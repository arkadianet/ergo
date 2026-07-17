//! Transaction-mode (indexed) [`ErgoBoxCandidate`] codec: token IDs are
//! written as `u32` indexes into the enclosing transaction's token table.

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::ergo_tree::{read_ergo_tree, ErgoTree};
use crate::error::WriteError;
use crate::register::read_registers;
use crate::token::{Token, TokenId};

use super::{check_token_count, ErgoBoxCandidate};

/// Serialize ErgoBoxCandidate in transaction mode (indexed token IDs).
pub fn write_ergo_box_candidate_indexed(
    w: &mut VlqWriter,
    c: &ErgoBoxCandidate,
    token_id_table: &[TokenId],
) -> Result<(), WriteError> {
    w.put_u64(c.value);
    w.put_bytes(&c.ergo_tree_bytes);
    w.put_u32(c.creation_height);
    check_token_count(c.tokens.len())?;
    w.put_u8(c.tokens.len() as u8);
    for token in &c.tokens {
        // Callers from `transaction.rs::write_transaction` derive the
        // table from the same outputs, so this lookup will always
        // succeed there. We surface the mismatch as a structured error
        // instead of a panic so direct callers (REST glue, fixtures)
        // get a recoverable failure if they ever pass an inconsistent
        // candidate / table pair.
        let idx = token_id_table
            .iter()
            .position(|id| id == &token.token_id)
            .ok_or_else(|| {
                let id_hex: String = token
                    .token_id
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                WriteError::InvalidData(format!(
                    "token_id {id_hex} not found in token_id_table while writing indexed output",
                ))
            })? as u32;
        w.put_u32(idx);
        w.put_u64(token.amount);
    }
    w.put_bytes(&c.register_bytes);
    Ok(())
}

/// Read ErgoBoxCandidate in transaction mode (indexed token IDs).
///
/// The opcode body parser deterministically finds the tree boundary for both
/// size-delimited and non-size-delimited ErgoTrees.
pub fn read_ergo_box_candidate_indexed(
    r: &mut VlqReader,
    token_id_table: &[TokenId],
) -> Result<ErgoBoxCandidate, ReadError> {
    let value = r.get_u64()?;
    let tree_start = r.position();
    let ergo_tree = read_ergo_tree(r)?;
    crate::ergo_tree::check_tree_version_supported(&ergo_tree)?;
    crate::ergo_tree::check_header_size_bit(&ergo_tree)?;
    crate::ergo_tree::check_resolvable_methods(&ergo_tree)?;
    crate::ergo_tree::check_sigma_prop_root(&ergo_tree)?;
    let tree_end = r.position();
    let ergo_tree_bytes = r.data_slice(tree_start, tree_end).to_vec();

    read_box_tail(r, value, ergo_tree, ergo_tree_bytes, token_id_table)
}

/// Read the box tail (creation_height, tokens, registers) and assemble the full candidate.
fn read_box_tail(
    r: &mut VlqReader,
    value: u64,
    ergo_tree: ErgoTree,
    ergo_tree_bytes: Vec<u8>,
    token_id_table: &[TokenId],
) -> Result<ErgoBoxCandidate, ReadError> {
    let creation_height = r.get_u32_exact()?;
    let token_count = r.get_u8()? as usize;
    let mut tokens = Vec::with_capacity(token_count);
    for _ in 0..token_count {
        let idx = r.get_u32_exact()? as usize;
        if idx >= token_id_table.len() {
            return Err(ReadError::InvalidData(format!(
                "token index {idx} out of bounds (table size {})",
                token_id_table.len()
            )));
        }
        let amount = r.get_u64()?;
        tokens.push(Token {
            token_id: token_id_table[idx],
            amount,
        });
    }
    let reg_start = r.position();
    let additional_registers = read_registers(r)?;
    let reg_end = r.position();
    let register_bytes = r.data_slice(reg_start, reg_end).to_vec();
    Ok(ErgoBoxCandidate {
        value,
        ergo_tree,
        ergo_tree_bytes,
        creation_height,
        tokens,
        additional_registers,
        register_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::Expr;
    use crate::register::AdditionalRegisters;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::SigmaValue;

    // ----- helpers -----

    fn size_delimited_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            // Root must be SSigmaProp: under `has_size`, a non-SigmaProp root
            // (e.g. `Const(SBoolean, true)`) fails Scala's
            // CheckDeserializedScriptIsSigmaProp and is soft-fork-wrapped into
            // `Expr::Unparsed` on re-parse, so it would not survive a
            // round-trip as a parsed body.
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(crate::sigma_value::SigmaBoolean::TrivialProp(true)),
            },
        }
    }

    fn make_token_id(fill: u8) -> TokenId {
        TokenId::from_bytes([fill; 32])
    }

    // ----- round-trips -----

    #[test]
    fn indexed_mode_roundtrip() {
        let token_id_table = vec![
            make_token_id(0x01),
            make_token_id(0x02),
            make_token_id(0x03),
        ];
        let tree = size_delimited_tree();
        let candidate = ErgoBoxCandidate::new(
            5_000_000,
            tree,
            200,
            vec![
                Token {
                    token_id: make_token_id(0x02),
                    amount: 100,
                },
                Token {
                    token_id: make_token_id(0x01),
                    amount: 200,
                },
                Token {
                    token_id: make_token_id(0x03),
                    amount: 300,
                },
            ],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        let mut w = VlqWriter::new();
        write_ergo_box_candidate_indexed(&mut w, &candidate, &token_id_table).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_ergo_box_candidate_indexed(&mut r, &token_id_table).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, candidate);
    }

    // ----- error paths -----

    #[test]
    fn indexed_mode_write_token_not_in_table_returns_invalid_data() {
        // When an output token id is missing from the supplied table,
        // `write_ergo_box_candidate_indexed` returns
        // `WriteError::InvalidData`. Direct callers — REST glue and
        // fixture tooling — rely on the recoverable error. Production
        // callers in `transaction.rs::write_transaction` derive the
        // table from the same outputs being written, so this branch
        // is unreachable from there.
        let in_table = make_token_id(0x01);
        let absent = make_token_id(0xFF);
        let token_id_table = vec![in_table];

        let tree = size_delimited_tree();
        let candidate = ErgoBoxCandidate::new(
            1_000_000,
            tree,
            100,
            vec![Token {
                token_id: absent,
                amount: 42,
            }],
            AdditionalRegisters::empty(),
        )
        .unwrap();

        let mut w = VlqWriter::new();
        let err = write_ergo_box_candidate_indexed(&mut w, &candidate, &token_id_table)
            .expect_err("write must reject token outside table");
        match err {
            WriteError::InvalidData(msg) => {
                assert!(
                    msg.contains("not found in token_id_table"),
                    "unexpected error message: {msg}",
                );
                // Hex of the missing token id should appear in the message
                // so operators can identify which token caused the mismatch.
                let absent_hex: String = absent
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert!(
                    msg.contains(&absent_hex),
                    "missing token id {absent_hex} not in error message: {msg}",
                );
            }
        }
    }

    #[test]
    fn indexed_mode_out_of_bounds() {
        let token_id_table = vec![make_token_id(0x01)];
        // Build a valid size-delimited tree with a simple body, then append
        // a box tail with an out-of-bounds token index.
        let tree = size_delimited_tree();
        let mut w = VlqWriter::new();
        w.put_u64(1_000_000); // value
        crate::ergo_tree::write_ergo_tree(&mut w, &tree).unwrap();
        w.put_u32(100); // creation_height
        w.put_u8(1); // 1 token
        w.put_u32(5); // index 5, out of bounds
        w.put_u64(100); // amount
        w.put_u8(0); // 0 registers
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let err = read_ergo_box_candidate_indexed(&mut r, &token_id_table).unwrap_err();
        assert!(matches!(err, ReadError::InvalidData(_)));
    }
}
