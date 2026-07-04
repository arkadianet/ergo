//! Cryptographic primitives for the Ergo Rust node.
//!
//! Sits one layer above [`ergo_primitives`] / [`ergo_ser`]: borrows the
//! Blake2b hasher, VLQ codecs, and consensus-typed `Header` /
//! `AutolykosSolution` structs, then layers chain-aware crypto on top.
//!
//! Module map:
//!
//! * [`autolykos`] — Autolykos v1 / v2 proof-of-work scheme. v1 uses
//!   secp256k1 EC equation arithmetic (`w^f == g^d * pk`); v2 uses a
//!   memory-hard Blake2b-only construction. Shared helpers (the `M`
//!   table, `gen_indexes`, `calc_n` height-dependent table size) live
//!   in [`autolykos::common`].
//! * [`difficulty`] — chain-aware difficulty adjustment: pre-EIP-37
//!   (predictive linear interpolation), EIP-37 (predictive ∪ classic,
//!   capped at ±50%), and the v2-activation special case. Network
//!   parameters are carried by [`difficulty::DifficultyParams`].
//! * [`merkle`] — Blake2b256 Merkle trees matching the scorex layout
//!   (leaf prefix `0x00`, internal prefix `0x01`, odd nodes paired with
//!   `EmptyNode = []`). Provides [`merkle::merkle_tree_root`],
//!   [`merkle::transactions_root`], [`merkle::extension_root`], and
//!   per-leaf [`merkle::merkle_proof_by_index`] inclusion proofs.
//! * [`pow`] — header-level PoW + difficulty verification entry points
//!   ([`pow::verify_pow_solution`], [`pow::verify_header_difficulty`]).
//!   Both take an explicit [`difficulty::DifficultyParams`] so the same code
//!   serves mainnet, testnet, and custom-network use.
//! * [`group_element`] — secp256k1 point decompression (`[u8; 33]` SEC1
//!   compressed → affine `(x, y)` hex) and on-curve validation. Used by
//!   `ergo-compiler` (M3) to render `GroupElement`/`ProveDlog` typed-AST
//!   constants in the Scala `Ecp.toString` `(x,y,1)` form.
//!
//! What is **not** here:
//!
//! * No script interpreter — ErgoTree evaluation lives in `ergo-sigma`.
//! * No AVL+ tree state — that's `ergo-state`.
//! * No header / transaction / box codecs — those are `ergo-ser`.
//! * No block-graph or fork-choice logic — that's `ergo-validation` /
//!   `ergo-state` / `ergo-sync`.

pub mod autolykos;
pub mod difficulty;
pub mod group_element;
pub mod merkle;
pub mod pow;
