//! Ergo box wire codecs.
//!
//! Split by direction and mode:
//!
//! * `mod.rs` — the [`ErgoBoxCandidate`] / [`ErgoBox`] data types
//!   (including the validating `try_from_raw_parts` constructor) and the
//!   shared `check_token_count` wire-cap helper.
//! * `candidate.rs` — standalone-mode candidate codec (full token IDs).
//! * `candidate_indexed.rs` — transaction-mode candidate codec (token IDs
//!   as indexes into the enclosing transaction's token table).
//! * `whole.rs` — whole-`ErgoBox` codec, `box_id` helpers, and the
//!   vector-assisted `parse_ergo_box_bytes`.

use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;

use crate::ergo_tree::{read_ergo_tree, write_ergo_tree, ErgoTree};
use crate::error::WriteError;
use crate::register::{read_registers, write_registers, AdditionalRegisters};
use crate::token::Token;

mod candidate;
mod candidate_indexed;
mod whole;

pub use candidate::{read_ergo_box_candidate, write_ergo_box_candidate};
pub use candidate_indexed::{read_ergo_box_candidate_indexed, write_ergo_box_candidate_indexed};
pub use whole::{
    box_id_with, parse_ergo_box_bytes, read_ergo_box, serialize_ergo_box, write_ergo_box,
};

/// Parsed box candidate with a structured ErgoTree.
///
/// The ErgoTree is stored in parsed form AND as raw bytes. The raw bytes
/// are used for wire-compatible serialization (the tree is written directly
/// into the box byte stream, matching Scala/sigma-rust behavior).
///
/// # Standalone parsing limitation
///
/// `read_ergo_box` / `read_ergo_box_candidate` can only locate the tree/body
/// boundary when the ErgoTree header has the size flag set. Non-size-delimited
/// trees (legal on mainnet, common in early blocks) require the caller to
/// supply the tree bytes externally — see `parse_ergo_box_bytes`. Transaction-
/// mode parsing (`read_ergo_box_candidate_indexed`) does not have this
/// limitation because the token table and field ordering provide the boundary.
///
/// Removing this limitation requires opcode-level expression parsing to
/// discover where the tree body ends. Until then, standalone raw-bytes box
/// parsing (UTXO snapshots, API responses) must use `parse_ergo_box_bytes`
/// for boxes with non-size-delimited trees.
#[derive(Debug, Clone, PartialEq)]
pub struct ErgoBoxCandidate {
    /// Box value in nanoErg.
    pub value: u64,
    ergo_tree: ErgoTree,
    ergo_tree_bytes: Vec<u8>,
    /// Block height at which this candidate is created (consensus
    /// rejects boxes whose `creation_height` is greater than the
    /// containing block's height).
    pub creation_height: u32,
    /// Tokens carried by the box, in their on-wire order.
    pub tokens: Vec<Token>,
    /// Non-mandatory registers R4-R9 (densely packed from R4 upward).
    pub additional_registers: AdditionalRegisters,
    register_bytes: Vec<u8>,
}

impl ErgoBoxCandidate {
    /// Build from an ErgoTree struct, serializing it to raw bytes.
    pub fn new(
        value: u64,
        ergo_tree: ErgoTree,
        creation_height: u32,
        tokens: Vec<Token>,
        additional_registers: AdditionalRegisters,
    ) -> Result<Self, WriteError> {
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &ergo_tree)?;
        let ergo_tree_bytes = w.result();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &additional_registers)?;
        let register_bytes = rw.result();
        Ok(Self {
            value,
            ergo_tree,
            ergo_tree_bytes,
            creation_height,
            tokens,
            additional_registers,
            register_bytes,
        })
    }

    /// Build from already-trusted parts, preserving verbatim ErgoTree and
    /// register bytes. Use this when reconstructing a box from external
    /// data the on-chain Scala node already accepted (REST mainnet replay,
    /// captured fixtures) and `box_id` byte-identity must hold.
    ///
    /// # Safety contract
    ///
    /// Caller MUST guarantee:
    /// - `ergo_tree_bytes` is the canonical serialization of `ergo_tree`
    /// - `register_bytes` is the canonical serialization of
    ///   `additional_registers`
    ///
    /// No runtime check is performed. A mismatch silently produces a
    /// candidate whose serialized bytes disagree with its parsed
    /// fields, desyncing `box_id` from inspection. Prefer
    /// [`ErgoBoxCandidate::try_from_raw_parts`] when the caller cannot
    /// guarantee the contract, or [`ErgoBoxCandidate::new`] when no
    /// external byte fixture is being preserved.
    pub fn from_trusted_raw_parts(
        value: u64,
        ergo_tree: ErgoTree,
        ergo_tree_bytes: Vec<u8>,
        creation_height: u32,
        tokens: Vec<Token>,
        additional_registers: AdditionalRegisters,
        register_bytes: Vec<u8>,
    ) -> Self {
        Self {
            value,
            ergo_tree,
            ergo_tree_bytes,
            creation_height,
            tokens,
            additional_registers,
            register_bytes,
        }
    }

    /// Validating counterpart to [`ErgoBoxCandidate::from_trusted_raw_parts`].
    ///
    /// Re-parses `ergo_tree_bytes` and `register_bytes` and checks the
    /// result equals the supplied `ergo_tree` / `additional_registers`.
    /// Returns `WriteError::InvalidData` on any mismatch — including
    /// re-parse failure, trailing bytes after parse, or a parse
    /// success that does not equal the supplied parsed value. On
    /// success the candidate carries the supplied raw bytes verbatim
    /// (so non-canonical Scala-emitted forms are preserved for
    /// `box_id` byte-identity).
    ///
    /// Cost: one re-parse of the tree and registers per call. Use
    /// this on construction paths where the caller cannot prove the
    /// invariant by construction; prefer the unchecked
    /// [`ErgoBoxCandidate::from_trusted_raw_parts`] in hot paths
    /// where the bytes/parsed pair is guaranteed (e.g. `read_ergo_box*`
    /// itself, which produces both atomically from the same reader).
    pub fn try_from_raw_parts(
        value: u64,
        ergo_tree: ErgoTree,
        ergo_tree_bytes: Vec<u8>,
        creation_height: u32,
        tokens: Vec<Token>,
        additional_registers: AdditionalRegisters,
        register_bytes: Vec<u8>,
    ) -> Result<Self, WriteError> {
        let mut tr = VlqReader::new(&ergo_tree_bytes);
        let parsed_tree = read_ergo_tree(&mut tr)
            .map_err(|e| WriteError::InvalidData(format!("ergo_tree_bytes do not parse: {e}")))?;
        crate::ergo_tree::check_tree_version_supported(&parsed_tree).map_err(|e| {
            WriteError::InvalidData(format!("ergo_tree_bytes have an unsupported version: {e}"))
        })?;
        crate::ergo_tree::check_header_size_bit(&parsed_tree).map_err(|e| {
            WriteError::InvalidData(format!("ergo_tree_bytes fail CheckHeaderSizeBit: {e}"))
        })?;
        crate::ergo_tree::check_resolvable_methods(&parsed_tree).map_err(|e| {
            WriteError::InvalidData(format!(
                "ergo_tree_bytes carry a method the tree's registry cannot resolve: {e}"
            ))
        })?;
        crate::ergo_tree::check_sigma_prop_root(&parsed_tree).map_err(|e| {
            WriteError::InvalidData(format!("ergo_tree_bytes have a non-SigmaProp root: {e}"))
        })?;
        if !tr.is_empty() {
            return Err(WriteError::InvalidData(
                "ergo_tree_bytes have trailing content after parse".into(),
            ));
        }
        if parsed_tree != ergo_tree {
            return Err(WriteError::InvalidData(
                "ergo_tree_bytes parse to a different tree than the supplied parsed value".into(),
            ));
        }

        let mut rr = VlqReader::new(&register_bytes);
        let parsed_registers = read_registers(&mut rr)
            .map_err(|e| WriteError::InvalidData(format!("register_bytes do not parse: {e}")))?;
        if !rr.is_empty() {
            return Err(WriteError::InvalidData(
                "register_bytes have trailing content after parse".into(),
            ));
        }
        if parsed_registers != additional_registers {
            return Err(WriteError::InvalidData(
                "register_bytes parse to different registers than the supplied parsed value".into(),
            ));
        }

        Ok(Self {
            value,
            ergo_tree,
            ergo_tree_bytes,
            creation_height,
            tokens,
            additional_registers,
            register_bytes,
        })
    }

    /// Borrow the parsed `ErgoTree` carried by this candidate.
    pub fn ergo_tree(&self) -> &ErgoTree {
        &self.ergo_tree
    }

    /// Verbatim canonical bytes of the `ErgoTree`. Preserved across
    /// parse so callers needing byte-exact roundtrip — including
    /// `box_id` computation — don't have to re-serialize through the
    /// writer.
    pub fn ergo_tree_bytes(&self) -> &[u8] {
        &self.ergo_tree_bytes
    }

    /// Verbatim bytes the parser preserved for `additional_registers`.
    ///
    /// Returned slice is the raw `count(u8) || concat(register_bytes)` wire
    /// form — feed it to `split_register_bytes` to recover per-register
    /// hex without round-tripping through the structured representation.
    /// Byte-equal to what came in off the wire.
    pub fn register_bytes(&self) -> &[u8] {
        &self.register_bytes
    }
}

/// A confirmed ergo box: an [`ErgoBoxCandidate`] plus the identity of
/// the transaction that minted it and the output index within that
/// transaction. The pair `(transaction_id, index)` is what `box_id` is
/// derived from when the candidate is sealed into a block.
#[derive(Debug, Clone, PartialEq)]
pub struct ErgoBox {
    /// The output candidate as defined in the minting transaction.
    pub candidate: ErgoBoxCandidate,
    /// Identifier of the transaction that produced this box.
    pub transaction_id: ModifierId,
    /// Output index of this box within `transaction_id`.
    pub index: u16,
}

impl ErgoBox {
    /// Compute the canonical `box_id` — `Blake2b256` of the box's
    /// serialized wire form (candidate body, then the 32-byte
    /// `transaction_id`, then the VLQ-`u16` `index`). See
    /// [`box_id_with`] for an allocation-free scratch variant.
    pub fn box_id(&self) -> Result<Digest32, WriteError> {
        let bytes = serialize_ergo_box(self)?;
        Ok(blake2b256(&bytes))
    }
}

/// Scala writes the per-box token count as a single unsigned byte;
/// >255 tokens would silently wrap on `as u8` and corrupt the wire form.
fn check_token_count(len: usize) -> Result<(), WriteError> {
    if len > u8::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "ErgoBox token count too large for Scala wire format: {len} (max 255)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::Expr;
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

    // ----- ErgoBoxCandidate::try_from_raw_parts validation -----

    #[test]
    fn try_from_raw_parts_accepts_matching_bytes() {
        let tree = size_delimited_tree();
        let mut tw = VlqWriter::new();
        crate::ergo_tree::write_ergo_tree(&mut tw, &tree).unwrap();
        let tree_bytes = tw.result();

        let regs = AdditionalRegisters::empty();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &regs).unwrap();
        let reg_bytes = rw.result();

        let cand = ErgoBoxCandidate::try_from_raw_parts(
            1_000_000,
            tree.clone(),
            tree_bytes.clone(),
            100,
            vec![],
            regs.clone(),
            reg_bytes.clone(),
        )
        .expect("matching bytes/parsed must succeed");

        // Bytes preserved verbatim.
        assert_eq!(cand.ergo_tree_bytes(), &tree_bytes[..]);
        assert_eq!(cand.register_bytes(), &reg_bytes[..]);
    }

    #[test]
    fn try_from_raw_parts_rejects_garbage_tree_bytes() {
        let tree = size_delimited_tree();
        let regs = AdditionalRegisters::empty();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &regs).unwrap();
        let reg_bytes = rw.result();

        let err = ErgoBoxCandidate::try_from_raw_parts(
            1_000_000,
            tree,
            vec![0xFF, 0xFF, 0xFF],
            100,
            vec![],
            regs,
            reg_bytes,
        )
        .unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("ergo_tree_bytes"),
            "msg should name field, got: {msg}"
        );
    }

    #[test]
    fn try_from_raw_parts_rejects_mismatched_tree() {
        // Build bytes for one tree, supply a different parsed tree.
        let tree_a = size_delimited_tree();
        let tree_b = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(false),
            },
        };
        assert_ne!(tree_a, tree_b);

        let mut tw = VlqWriter::new();
        crate::ergo_tree::write_ergo_tree(&mut tw, &tree_a).unwrap();
        let tree_a_bytes = tw.result();

        let regs = AdditionalRegisters::empty();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &regs).unwrap();
        let reg_bytes = rw.result();

        let err = ErgoBoxCandidate::try_from_raw_parts(
            1_000_000,
            tree_b,
            tree_a_bytes,
            100,
            vec![],
            regs,
            reg_bytes,
        )
        .unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("different tree"),
            "msg should describe mismatch, got: {msg}",
        );
    }

    #[test]
    fn try_from_raw_parts_rejects_trailing_tree_bytes() {
        let tree = size_delimited_tree();
        let mut tw = VlqWriter::new();
        crate::ergo_tree::write_ergo_tree(&mut tw, &tree).unwrap();
        let mut tree_bytes = tw.result();
        tree_bytes.push(0x00); // trailing byte

        let regs = AdditionalRegisters::empty();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &regs).unwrap();
        let reg_bytes = rw.result();

        let err = ErgoBoxCandidate::try_from_raw_parts(
            1_000_000,
            tree,
            tree_bytes,
            100,
            vec![],
            regs,
            reg_bytes,
        )
        .unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("trailing"),
            "msg should mention trailing, got: {msg}"
        );
    }
}
