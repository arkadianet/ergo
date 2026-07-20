//! Layer-1 crypto primitives for the EIP-0045 `verifyStark` raw-seal STARK
//! verifier — a faithful Rust port of the reference sigmastate verifier's
//! foundation.
//!
//! This crate is a leaf: it depends only on the proven `blake2` and `sha2`
//! hashing crates and has no dependency on `ergo-sigma`. Later layers
//! (Merkle/FRI, the circuit, the verifier core) build on the primitives
//! exported here, and the `verifyStark` opcode ultimately calls into them.
//!
//! Every primitive mirrors the reference exactly — arithmetic, Montgomery
//! encoding, Poseidon2 round constants and round structure, and the
//! Fiat-Shamir challenge derivation — and is pinned by Known Answer Tests
//! taken from the reference's own oracle vectors (`test-vectors/ergo-stark/`),
//! per the oracle-parity rule. Correctness against the Scala reference node is
//! the authoritative tie-breaker, never a self-oracle.
//!
//! # Modules
//! - [`baby_bear`] — the `p = 15·2^27 + 1` prime field (canonical values,
//!   Montgomery raw/canonical boundary conversions).
//! - [`ext4`] — the degree-4 extension `F_p[x]/(x^4 + 11)`.
//! - [`poseidon2`] — the Poseidon2-BabyBear width-24 permutation and sponge.
//! - [`read_iop`] — the verifier-side proof-word transcript reader and its
//!   Fiat-Shamir RNG.
//! - [`hash`] — the BLAKE2b-256 and SHA-256 profile hashers.
//! - [`merkle`] — the IOP Merkle branch verifier (Layer 2).
//! - [`fri`] — the FRI low-degree-test verifier (Layer 2).

pub mod baby_bear;
pub mod ext4;
pub mod hash;
mod poseidon2_constants;
pub mod read_iop;

pub mod poseidon2;

pub mod fri;
pub mod merkle;

pub use baby_bear::BabyBear;
pub use ext4::Ext4;
pub use merkle::MerkleVerifier;
pub use poseidon2::Poseidon2;
pub use poseidon2_constants::{CELLS, ROUNDS_HALF_FULL, ROUNDS_PARTIAL};
pub use read_iop::ReadIop;
