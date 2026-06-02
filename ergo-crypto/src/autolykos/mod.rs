//! Autolykos proof-of-work scheme.
//!
//! Two protocol versions live side-by-side. Header version 1 (heights
//! < 417,792 on mainnet) uses the secp256k1 EC equation
//! `w^f == g^d * pk`; header version 2+ uses a memory-hard
//! Blake2b-only construction with a height-dependent table size.
//!
//! The split:
//!
//! * [`common`] — pieces shared between versions: the precomputed
//!   `M_BYTES` table, `gen_indexes`, the height-dependent `calc_n`,
//!   and the local `blake2b256` helper.
//! * [`v1`] — Autolykos v1 verification (`check_pow_v1`) plus the
//!   secp256k1 group order and the `hashModQ` rejection-sampling hash.
//! * [`v2`] — Autolykos v2 verification (`check_pow_v2`) plus the
//!   `hit_for_v2` hit-computation primitive used at validation time.

pub mod common;
pub mod v1;
pub mod v2;
