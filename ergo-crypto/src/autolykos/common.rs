use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use num_bigint::BigUint;

type Blake2b256 = Blake2b<U32>;

/// Autolykos k parameter: number of elements in one solution.
pub const AUTOLYKOS_K: usize = 32;

/// Autolykos n parameter: NBase = 2^n.
pub const AUTOLYKOS_N: u32 = 26;

/// Base table size: 2^26 = 67,108,864.
pub const AUTOLYKOS_N_BASE: u32 = 1 << AUTOLYKOS_N;

/// Height at which N starts increasing (600 * 1024 = 614,400).
const INCREASE_START: u32 = 600 * 1024;

/// N increases every 50 * 1024 = 51,200 blocks.
const INCREASE_PERIOD: u32 = 50 * 1024;

/// N stops growing at this height. Max N = 2,143,944,600 < 2^31.
const N_INCREASE_HEIGHT_MAX: u32 = 4_198_400;

/// Constant M: 8192 bytes = (0..1024) as big-endian i64 values.
/// Used to increase hash computation time in genElement.
pub const M_BYTES: [u8; 8192] = {
    let mut m = [0u8; 8192];
    let mut i: u64 = 0;
    while i < 1024 {
        let bytes = i.to_be_bytes();
        let base = i as usize * 8;
        m[base] = bytes[0];
        m[base + 1] = bytes[1];
        m[base + 2] = bytes[2];
        m[base + 3] = bytes[3];
        m[base + 4] = bytes[4];
        m[base + 5] = bytes[5];
        m[base + 6] = bytes[6];
        m[base + 7] = bytes[7];
        i += 1;
    }
    m
};

/// Calculate table size N for a given header version and height.
/// v1 always uses NBase. v2+ grows N by 5% every `INCREASE_PERIOD` blocks
/// starting at `INCREASE_START`, capping at `N_INCREASE_HEIGHT_MAX`.
pub fn calc_n(version: u8, height: u32) -> u32 {
    if version == 1 {
        return AUTOLYKOS_N_BASE;
    }
    let height = height.min(N_INCREASE_HEIGHT_MAX);
    if height < INCREASE_START {
        return AUTOLYKOS_N_BASE;
    }
    let iters = (height - INCREASE_START) / INCREASE_PERIOD + 1;
    let mut n = AUTOLYKOS_N_BASE;
    for _ in 0..iters {
        // Integer arithmetic matching Scala: step / 100 * 105
        n = n / 100 * 105;
    }
    n
}

/// Blake2b256 hash.
pub fn blake2b256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Generate k=32 indices from a seed, each in [0, N).
/// Matches Scala `genIndexes`: hash the seed, extend with first 3 bytes,
/// then take 32 overlapping 4-byte slices interpreted as big-endian unsigned
/// integers mod N.
pub fn gen_indexes(seed: &[u8], n: u32) -> [u32; AUTOLYKOS_K] {
    let v = gen_indexes_k(seed, AUTOLYKOS_K, n);
    let mut out = [0u32; AUTOLYKOS_K];
    out.copy_from_slice(&v);
    out
}

/// Generalized `genIndexes` for an arbitrary index count `k`, matching
/// Scala `Autolykos2PowValidation.genIndexes(k, seed, N)`. Used by
/// `SGlobal.powHit`. The extended hash is `hash ++ hash[0..3]` (35
/// bytes), which supports `k <= 32`; callers (powHit) enforce that
/// bound. Each index is a 4-byte big-endian window mod N.
pub fn gen_indexes_k(seed: &[u8], k: usize, n: u32) -> Vec<u32> {
    debug_assert!(
        k <= 32,
        "gen_indexes_k: k must be <= 32 (35-byte extended hash)"
    );
    let hash = blake2b256(seed);
    // extended_hash = hash ++ hash[0..3] = 35 bytes
    let mut extended = [0u8; 35];
    extended[..32].copy_from_slice(&hash);
    extended[32..35].copy_from_slice(&hash[..3]);

    let n_big = BigUint::from(n);
    let mut indexes = Vec::with_capacity(k);
    for i in 0..k {
        let slice = &extended[i..i + 4];
        let val_big = BigUint::from_bytes_be(slice);
        let idx = val_big % &n_big;
        // Safe: idx < n < 2^31
        indexes.push(idx.to_u32_digits().first().copied().unwrap_or(0));
    }
    indexes
}

/// Convert a byte slice to BigUint (unsigned, big-endian).
pub fn to_big_int(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// Convert a `BigUint` to a 32-byte big-endian array, left-padding
/// shorter values with zeros and truncating longer ones to the low
/// 32 bytes. Mirrors Java `BigIntegers.asUnsignedByteArray(32, value)`
/// — used at the v1 EC equation path through `biguint_to_scalar`
/// (to derive a `k256::FieldBytes`) and at the v2 final-hash step.
pub(super) fn biguint_to_32bytes(val: &BigUint) -> [u8; 32] {
    let bytes = val.to_bytes_be();
    let mut out = [0u8; 32];
    if bytes.len() >= 32 {
        out.copy_from_slice(&bytes[bytes.len() - 32..]);
    } else {
        out[32 - bytes.len()..].copy_from_slice(&bytes);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn calc_n_v1_always_returns_nbase() {
        assert_eq!(calc_n(1, 0), AUTOLYKOS_N_BASE);
        assert_eq!(calc_n(1, 1_000_000), AUTOLYKOS_N_BASE);
    }

    #[test]
    fn calc_n_v2_below_increase_start_returns_nbase() {
        assert_eq!(calc_n(2, 0), AUTOLYKOS_N_BASE);
        assert_eq!(calc_n(2, INCREASE_START - 1), AUTOLYKOS_N_BASE);
    }

    #[test]
    fn calc_n_v2_at_increase_start_grows_by_5_percent() {
        // At INCREASE_START, iters = 1, so N = NBase / 100 * 105
        let expected = AUTOLYKOS_N_BASE / 100 * 105;
        assert_eq!(calc_n(2, INCREASE_START), expected);
    }

    #[test]
    fn calc_n_v2_caps_at_max_height() {
        let at_max = calc_n(2, N_INCREASE_HEIGHT_MAX);
        let beyond = calc_n(2, N_INCREASE_HEIGHT_MAX + 1_000_000);
        assert_eq!(at_max, beyond);
    }

    #[test]
    fn m_bytes_layout_matches_scala_const() {
        // M[0..8] should be 0i64.to_be_bytes() = all zeros
        assert_eq!(&M_BYTES[0..8], &[0u8; 8]);
        // M[8..16] should be 1i64.to_be_bytes()
        assert_eq!(&M_BYTES[8..16], &1u64.to_be_bytes());
        // M[8184..8192] should be 1023i64.to_be_bytes()
        assert_eq!(&M_BYTES[8184..8192], &1023u64.to_be_bytes());
    }

    #[test]
    fn gen_indexes_returns_k_indices_within_n_range() {
        let seed = blake2b256(b"test seed");
        let indexes = gen_indexes(&seed, AUTOLYKOS_N_BASE);
        assert_eq!(indexes.len(), AUTOLYKOS_K);
        for &idx in &indexes {
            assert!(idx < AUTOLYKOS_N_BASE);
        }
    }

    /// `gen_indexes_k(seed, k, N)` for any `k <= 32` is exactly the first
    /// `k` indices of the k=32 `gen_indexes` — both share the 35-byte
    /// extended hash and the same sliding 4-byte window. The only external
    /// powHit oracles (the mainnet corpus and the sigmastate v6.0.2 KAT)
    /// pin k=32; this prefix property anchors every `k < 32` index set to
    /// that validated generation, so a correct k=32 implies a correct
    /// k<32 (the powHit element sum is the same loop over fewer indices).
    #[test]
    fn gen_indexes_k_is_prefix_of_k32_for_all_valid_k() {
        let seed = blake2b256(b"powhit prefix property seed");
        let full = gen_indexes(&seed, AUTOLYKOS_N_BASE);
        for k in 2usize..=32 {
            let partial = gen_indexes_k(&seed, k, AUTOLYKOS_N_BASE);
            assert_eq!(partial.as_slice(), &full[..k], "k={k} must prefix k=32");
        }
    }
}
