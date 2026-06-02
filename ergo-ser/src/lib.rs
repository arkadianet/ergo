//! Consensus-typed wire-format codecs for the Ergo Rust node.
//!
//! `ergo-ser` sits one layer above [`ergo_primitives`]: it borrows
//! `VlqReader` / `VlqWriter` and the basic digest / group-element types,
//! then layers consensus-typed reads and writes on top. Every module here
//! must round-trip a witness drawn from mainnet bytes.
//!
//! Module map:
//!
//! * [`header`] / [`block_transactions`] / [`ad_proofs`] / [`extension`] —
//!   block-section codecs (header, transactions list, AVL state proofs,
//!   miner-voting extension).
//! * [`transaction`] / [`input`] / [`ergo_box`] / [`token`] / [`register`] —
//!   transaction-level codecs and the supporting box / input / token /
//!   register layouts.
//! * [`ergo_tree`] / [`opcode`] / [`sigma_type`] / [`sigma_value`] —
//!   ErgoTree wire format: tree header + constants + body, the opcode
//!   dispatch table, and the sigma type / value codecs invoked by both.
//! * [`address`] — base58 P2PK / P2SH / P2S address encoding.
//! * [`autolykos`] — Autolykos v2 PoW solution wire form.
//! * [`difficulty`] — `nBits` compact-bits encoding shared with Bitcoin.
//!
//! What is **not** here:
//!
//! * No block / transaction validation. Acceptance rules live in
//!   `ergo-validation`; this crate only converts bytes ↔ structs.
//! * No interpreter. ErgoTree evaluation lives in `ergo-sigma`.
//! * No AVL+ tree state. Authenticated state lives in `ergo-state`.
//! * No JSON shapes. The REST envelope and Scala-compatible JSON
//!   round-trips live in `ergo-rest-json`.

pub mod ad_proofs;
pub mod address;
pub mod autolykos;
pub mod batch_merkle_proof;
pub mod block_transactions;
pub mod difficulty;
pub mod ergo_box;
pub mod ergo_tree;
pub mod error;
pub mod extension;
pub mod header;
pub mod input;
pub mod modifier_id;
pub mod opcode;
pub mod popow_header;
pub mod popow_proof;
pub mod register;
pub mod scala_hamt;
pub mod sigma_type;
pub mod sigma_value;
pub mod token;
pub mod transaction;

pub use error::WriteError;
