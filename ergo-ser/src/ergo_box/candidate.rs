//! Standalone-mode [`ErgoBoxCandidate`] codec (full 32-byte token IDs).

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::ergo_tree::read_ergo_tree;
use crate::error::WriteError;
use crate::register::read_registers;
use crate::token::{Token, TokenId};

use super::{check_token_count, ErgoBoxCandidate};

/// Serialize ErgoBoxCandidate in standalone mode (full token IDs).
///
/// Writes the raw ErgoTree bytes directly (no length prefix), matching
/// the Scala/sigma-rust wire format.
pub fn write_ergo_box_candidate(w: &mut VlqWriter, c: &ErgoBoxCandidate) -> Result<(), WriteError> {
    w.put_u64(c.value);
    w.put_bytes(&c.ergo_tree_bytes);
    w.put_u32(c.creation_height);
    check_token_count(c.tokens.len())?;
    w.put_u8(c.tokens.len() as u8);
    for token in &c.tokens {
        w.put_bytes(token.token_id.as_bytes());
        w.put_u64(token.amount);
    }
    w.put_bytes(&c.register_bytes);
    Ok(())
}

/// Read ErgoBoxCandidate in standalone mode (full token IDs).
///
/// The ErgoTree is parsed from the stream. For size-delimited trees (has_size
/// flag set in header), this works directly. For non-size-delimited trees,
/// the `read_ergo_tree` call consumes all remaining bytes as the tree body,
/// so this function only works when the reader is bounded to exact box data.
///
/// For parsing real mainnet box bytes (which may have non-size-delimited trees),
/// use `parse_ergo_box_bytes` which handles tree boundary detection.
pub fn read_ergo_box_candidate(r: &mut VlqReader) -> Result<ErgoBoxCandidate, ReadError> {
    let value = r.get_u64()?;
    let tree_start = r.position();
    let ergo_tree = read_ergo_tree(r)?;
    // Box-script ACCEPTANCE gates. Skipped only when the reader is decoding a
    // TRUSTED, already-validated source (`VlqReader::trusted` — set ONLY by the
    // indexer when re-reading its own stored `INDEXED_BOX` rows). A legacy stored
    // row can carry a high-version size-delimited (opaque) ErgoTree that these
    // gates hard-reject; re-validating consensus while reading the node's own
    // already-accepted data is wrong and makes the row (and the rebuild that
    // scans it, and apply/rollback/API materialization) unreadable. The
    // structural `read_ergo_tree` parse above already ran, so `ergo_tree_bytes` /
    // template-hash derivation are identical either way. For untrusted block /
    // transaction bytes the reader is NOT trusted, so these run exactly as
    // before — the consensus path is byte-for-byte unchanged.
    if !r.is_trusted() {
        crate::ergo_tree::check_tree_version_supported(&ergo_tree)?;
        crate::ergo_tree::check_header_size_bit(&ergo_tree)?;
        crate::ergo_tree::check_resolvable_methods(&ergo_tree)?;
        crate::ergo_tree::check_sigma_prop_root(&ergo_tree)?;
    }
    let tree_end = r.position();
    let ergo_tree_bytes = r.data_slice(tree_start, tree_end).to_vec();
    let creation_height = r.get_u32_exact()?;
    let token_count = r.get_u8()? as usize;
    let mut tokens = Vec::with_capacity(token_count);
    for _ in 0..token_count {
        let token_id = TokenId::from_bytes(r.get_array::<32>()?);
        let amount = r.get_u64()?;
        tokens.push(Token { token_id, amount });
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
    use crate::ergo_tree::ErgoTree;
    use crate::opcode::Expr;
    use crate::register::{AdditionalRegisters, RegisterValue};
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::SigmaValue;

    use super::super::write_ergo_box_candidate_indexed;

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

    fn make_candidate(tree: &ErgoTree) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            1_000_000_000,
            tree.clone(),
            500_000,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn make_token_id(fill: u8) -> TokenId {
        TokenId::from_bytes([fill; 32])
    }

    // ----- CheckHeaderSizeBit (rule 1012) on box scripts -----

    /// A box candidate whose script is a version-3 ErgoTree with the size bit
    /// CLEAR must be REJECTED: Scala `CheckHeaderSizeBit` (rule 1012, in
    /// `deserializeErgoTree`) requires the size bit for any non-zero version, so
    /// old nodes can skip an unknown tree by its declared length. `read_ergo_tree`
    /// stays lenient (the conformance hook feeds it size-stripped trees), so the
    /// box-candidate reader enforces it. Bytes: value(VLQ 1000) ++ tree
    /// `03 05 01` (v3, no-size, body Const(SLong,-1)) ++ height(0) ++ 0 tokens ++
    /// 0 regs — which currently parses end-to-end (accept-invalid).
    #[test]
    fn box_candidate_v3_script_without_size_bit_rejected() {
        let bytes = [0xE8u8, 0x07, 0x03, 0x05, 0x01, 0x00, 0x00, 0x00];
        let mut r = VlqReader::new(&bytes);
        let res = read_ergo_box_candidate(&mut r);
        assert!(
            res.is_err(),
            "v3-no-size box script must be rejected (CheckHeaderSizeBit), got {res:?}"
        );
    }

    /// A version-0 script with no size bit is the COMMON, valid case (P2PK etc.) —
    /// CheckHeaderSizeBit only requires the bit for version != 0, so it must parse.
    /// The body must still be a SigmaProp root (`CheckDeserializedScriptIsSigmaProp`,
    /// rule 1001): here `08 d3` is `Const(SSigmaProp, TrueProp)`.
    #[test]
    fn box_candidate_v0_script_without_size_bit_ok() {
        // value(VLQ 1000) ++ tree `00 08 d3` (v0, no-size, body Const(SSigmaProp,true))
        // ++ height(0) ++ 0 tokens ++ 0 regs.
        let bytes = [0xE8u8, 0x07, 0x00, 0x08, 0xD3, 0x00, 0x00, 0x00];
        let mut r = VlqReader::new(&bytes);
        let res = read_ergo_box_candidate(&mut r);
        assert!(res.is_ok(), "v0-no-size box script must parse, got {res:?}");
    }

    // ----- round-trips -----

    #[test]
    fn candidate_roundtrip_no_tokens_no_registers() {
        let tree = size_delimited_tree();
        let candidate = make_candidate(&tree);
        let mut w = VlqWriter::new();
        write_ergo_box_candidate(&mut w, &candidate).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_ergo_box_candidate(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, candidate);
    }

    #[test]
    fn candidate_roundtrip_with_tokens_and_registers() {
        let tree = size_delimited_tree();
        let candidate = ErgoBoxCandidate::new(
            67_500_000_000,
            tree,
            800_000,
            vec![
                Token {
                    token_id: make_token_id(0xAA),
                    amount: 1_000,
                },
                Token {
                    token_id: make_token_id(0xBB),
                    amount: 999_999,
                },
            ],
            AdditionalRegisters {
                registers: vec![RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(42),
                }],
            },
        )
        .unwrap();
        let mut w = VlqWriter::new();
        write_ergo_box_candidate(&mut w, &candidate).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_ergo_box_candidate(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, candidate);
    }

    // ----- error paths -----

    #[test]
    fn write_candidate_above_255_tokens_returns_invalid_data() {
        // Scala's `ErgoBoxCandidate.serializer` writes the token count as
        // a single unsigned byte; a candidate with > 255 tokens is a
        // wire-format violation. Direct callers (REST, mempool synthetic
        // setup, fixture tooling) need a recoverable `WriteError` rather
        // than a panic.
        let tree = size_delimited_tree();
        let token = Token {
            token_id: make_token_id(0xAB),
            amount: 1,
        };
        let candidate = ErgoBoxCandidate::new(
            1_000_000,
            tree,
            100,
            vec![token; 256],
            AdditionalRegisters::empty(),
        )
        .unwrap();

        let mut w = VlqWriter::new();
        let err = write_ergo_box_candidate(&mut w, &candidate).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("256"),
            "message should name the count, got: {msg}"
        );
        assert!(
            msg.contains("max 255"),
            "message should name the cap, got: {msg}"
        );

        // Indexed-mode writer mirrors the same cap.
        let table = vec![make_token_id(0xAB)];
        let mut w2 = VlqWriter::new();
        let err2 = write_ergo_box_candidate_indexed(&mut w2, &candidate, &table).unwrap_err();
        let WriteError::InvalidData(msg2) = &err2;
        assert!(
            msg2.contains("256"),
            "indexed: message should name count, got: {msg2}"
        );
    }
}
