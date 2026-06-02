//! Sigma-protocol verifier and ErgoTree evaluator for the Ergo Rust node.
//!
//! Sits on top of [`ergo_primitives`] (Blake2b digests, JIT cost
//! accumulator) and [`ergo_ser`] (parsed `ErgoTree`, sigma values,
//! opcodes). Depends on `ergo-crypto` only for the `Header.checkPow`
//! SMethod (`ergo_crypto::pow::verify_pow_solution`); all sigma-proof
//! crypto (Schnorr, DHTuple, AVL+ proofs) is carried directly by `k256`
//! / `sha2` / the `gf2_192` polynomial library, since interpreter-side
//! crypto is performance-sensitive in a way the higher-level
//! `ergo-crypto` wrappers aren't.
//!
//! Module map:
//!
//! * [`evaluator`] — AST-walking interpreter that reduces an ErgoTree
//!   body to a [`SigmaBoolean`](ergo_ser::sigma_value::SigmaBoolean).
//!   Holds the opcode dispatch table and the per-opcode cost-charging
//!   logic. The largest module in the workspace; deliberately not
//!   split per-opcode because opcode interdependencies make a flat
//!   layout simpler than a partitioned one.
//! * [`reduce`] — fast trivial-reduction path: most P2PK / SigmaProp
//!   constants don't need the full evaluator, just a constant lookup.
//!   Provides [`reduce::verify_spending_proof_with_context`] — the
//!   single entry point spending validation calls.
//! * [`verify`] — sigma-proof verification (Schnorr DLog, DHTuple,
//!   `CAND` / `COR` / `Cthreshold` composition). Consumes a reduced
//!   [`SigmaBoolean`](ergo_ser::sigma_value::SigmaBoolean) and the
//!   proof bytes, returns `bool`.
//! * [`schnorr`] — secp256k1 Schnorr proof primitive used by `verify`.
//! * [`dht`] — Diffie-Hellman tuple proof primitive used by `verify`.
//! * [`cost_table`] — opcode cost rows mirroring sigmastate-interpreter's
//!   cost model. Drives the JIT-cost charge at every dispatch site.
//! * [`crypto_cost`] — sigma-tree crypto cost estimator
//!   (`estimate_crypto_cost`) — the cost added once per reduced
//!   proposition before the actual proof verification runs.
//! * [`avl`] — thin wrapper around `ergo_avltree_rust` for AVL+ proof
//!   verification. Single dependency boundary so the rest of the
//!   evaluator never imports the underlying crate.
//! * `cost_trace` (feature `cost-trace`) — debug-only per-step cost
//!   recorder for diagnosing divergence against the Scala oracle.

pub mod avl;
pub mod cost_table;
#[cfg(feature = "cost-trace")]
pub mod cost_trace;
pub mod crypto_cost;
pub mod dht;
pub mod evaluator;
pub mod reduce;
pub mod schnorr;
pub mod verify;

/// Fiat-Shamir challenge size: 192 bits = 24 bytes.
pub const SOUNDNESS_BYTES: usize = 24;

/// secp256k1 group order size: 256 bits = 32 bytes.
pub const GROUP_SIZE: usize = 32;

/// Total proof size for a standalone DLog (Schnorr) proof.
pub const SCHNORR_PROOF_SIZE: usize = SOUNDNESS_BYTES + GROUP_SIZE; // 56 bytes

/// Blake2b-256 hash returning raw bytes.
///
/// Delegates to [`ergo_primitives::digest::blake2b256`] and unwraps the
/// `Digest32` wrapper, since sigma protocol internals operate on `[u8; 32]`.
pub fn blake2b256(input: &[u8]) -> [u8; 32] {
    *ergo_primitives::digest::blake2b256(input).as_bytes()
}
