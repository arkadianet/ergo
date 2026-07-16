//! NiPoPoW (Non-Interactive Proofs of Proof-of-Work) primitives.
//!
//! Implements the pure algorithms from KMZ17 (FC20) that the proof
//! verifier and the boot orchestration build on:
//!
//! * [`algos::max_level_of`] — μ-level of a header (KMZ17 §2.2).
//! * [`algos::best_arg`] — best argument score of a chain (Algorithm 4).
//! * [`algos::lowest_common_ancestor`] — last shared header between
//!   two chains, iff they share a genesis.
//! * [`algos::update_interlinks`] — interlinks vector update rule.
//!
//! Mirrors Scala
//! `ergo-core/.../modifiers/history/popow/NipopowAlgos.scala`
//! field-for-field. The Scala source remains the consensus oracle
//! whenever this Rust port and the Scala node disagree.
//!
//! [`algos`] itself does no I/O and holds no state. Callers feed parsed
//! [`ergo_ser::header::Header`] values and interlinks read out of an
//! [`ergo_ser::extension::Extension`]. Stateful pieces (proof verifier,
//! quorum reducer, sync orchestration) live in the sibling [`proof`] and
//! [`verifier`] modules.

pub mod algos;
pub mod merkle;
pub mod proof;
pub mod verifier;

pub use algos::{
    best_arg, best_arg_from_levels, lowest_common_ancestor, max_level_of, update_interlinks,
    GENESIS_LEVEL,
};
pub use merkle::verify_batch_merkle_proof;
pub use proof::NipopowProofExt;
pub use verifier::{NipopowVerificationResult, NipopowVerifier};
