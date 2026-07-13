//! Shared JSON ↔ canonical-wire-bytes layer for Scala-compat REST.
//!
//! Hosts the JSON DTOs (matching Scala's `JsonCodecs`/`Header.jsonEncoder`/
//! `BlockTransactions.jsonEncoder`/`Extension.jsonEncoder`/etc. shapes)
//! plus the canonicalizing decoders that turn parsed JSON back into
//! the wire bytes the indexer / validator / persistence layer expect.
//!
//! The decoders are anchored by the b4_* byte-parity oracle in
//! `ergo-node/src/api_bridge.rs` — Scala-captured JSON inputs MUST
//! reconstruct byte-identical canonical wire output, including the
//! tx-submission-edge-case contracts (Q1: ignore-vs-reject for synthetic
//! sealing fields; Q2: empty-AdProofs handling; Q3: hex casing; Q4:
//! BigInt rejection; Q5: input-cap and depth-cap bounds).

pub mod decode;
pub mod mining;
pub mod types;

pub use decode::{
    decode_ad_proofs, decode_block_transactions_with_mode, decode_context_extension,
    decode_context_extension_with_mode, decode_ergo_tree_canonicalize,
    decode_ergo_tree_canonicalize_with_mode, decode_extension, decode_header_json, decode_input,
    decode_input_with_mode, decode_nipopow_proof_json, decode_output_with_mode, decode_registers,
    decode_registers_with_mode, decode_scala_full_block, decode_scala_header,
    decode_scala_header_struct, decode_scala_nipopow_proof, decode_scala_popow_header,
    decode_scala_transaction, decode_scala_transaction_with_mode, DecodeError, DecodeMode,
    DecodedFullBlock, DESERIALIZE, NON_CANONICAL,
};
pub use types::{
    ScalaAdProofs, ScalaAsset, ScalaBlockSection, ScalaBlockTransactions, ScalaDataInput,
    ScalaExtension, ScalaFullBlock, ScalaHeader, ScalaInput, ScalaOutput, ScalaOutputInput,
    ScalaPowSolutions, ScalaSpendingProof, ScalaTransaction, ScalaTransactionInput,
};
