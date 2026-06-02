//! Sigma proof production for the wallet.
//!
//! Mirrors Scala `ErgoProvingInterpreter` + `sigmastate.interpreter`.
//! - `hints`        — `HintsBag` + `TransactionHintsBag` (per-input, secret/public partition)
//! - `secrets`      — `SecretRegistry`: HD-secret lookup (ProveDlog(pk) → Scalar)
//! - `external`     — `ProverExternalSecret`: wallet-internal post-decode external secret
//! - `randomness`   — `ProvingRng` abstraction (OsRng + deterministic test RNG)
//! - `schnorr`      — Schnorr (ProveDlog) proof production
//! - `dht`          — Diffie-Hellman tuple (ProveDHTuple) proof production
//! - `sigma`        — Compound AND/OR/threshold proof composition
//! - `prover`       — `Prover` orchestrator: signs every input of a transaction
//! - `commitments`  — multi-sig commitment collection + aggregation
//! - `extract`      — proof-tree extraction helpers for multi-sig
//! - `node_position` — sigma-tree node addressing for multi-sig hint routing

pub mod commitments;
pub mod dht;
pub mod external;
pub mod extract;
pub mod hints;
pub mod node_position;
pub mod prover;
pub mod randomness;
pub mod schnorr;
pub mod secrets;
pub mod sigma;
