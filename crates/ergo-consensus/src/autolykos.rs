//! Autolykos v2 Proof-of-Work verification.
//!
//! Ports `AutolykosPowScheme.scala` from the Ergo reference implementation.
//! For v2, this is purely hash-based with no elliptic curve operations.

use std::sync::LazyLock;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use num_bigint::BigUint;
use num_traits::Zero;
use thiserror::Error;

use ergo_types::header::Header;
use ergo_wire::header_ser::serialize_header_without_pow;

use crate::difficulty::decode_compact_bits;

// ---------------------------------------------------------------------------
// Type alias for Blake2b with 256-bit output
// ---------------------------------------------------------------------------
type Blake2b256 = Blake2b<U32>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of indexes generated per PoW round.
pub const K: usize = 32;

/// Exponent for the base table size: N_BASE = 2^n.
const N: u32 = 26;

/// Base table size: 2^26 = 67_108_864.
pub const N_BASE: u32 = 1 << N;

/// Height at which the table size starts increasing.
pub const INCREASE_START: u32 = 600 * 1024; // 614_400

/// Period (in blocks) between each 5% increase in table size.
const INCREASE_PERIOD_FOR_N: u32 = 50 * 1024; // 51_200

/// Maximum height considered for table size increases.
const N_INCREASEMENT_HEIGHT_MAX: u32 = 4_198_400;

/// The secp256k1 group order `q`.
pub static Q: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .expect("Q constant is valid hex")
});

/// The precomputed constant `M`: 1024 long values (0..1024) each as 8-byte big-endian.
/// Total size: 1024 * 8 = 8192 bytes.
pub static M: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut m = Vec::with_capacity(8192);
    for i in 0u64..1024 {
        m.extend_from_slice(&i.to_be_bytes());
    }
    m
});

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from Autolykos PoW verification.
#[derive(Debug, Error)]
pub enum AutolykosError {
    /// The PoW hit does not satisfy the required difficulty target.
    #[error("PoW validation failed: hit {hit} >= target {target}")]
    InvalidPow {
        hit: String,
        target: String,
    },

    /// Only v2 headers are supported by this verification path.
    #[error("unsupported Autolykos version: {0}")]
    UnsupportedVersion(u8),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Validate the proof-of-work for a block header.
///
/// Computes the PoW hit and checks that `hit < q / decode_compact_bits(nBits)`.
pub fn validate_pow(header: &Header) -> Result<(), AutolykosError> {
    if header.version < 2 {
        return Err(AutolykosError::UnsupportedVersion(header.version));
    }

    let hit = hit_for_version2(header);
    let target = get_b(header.n_bits);

    if hit < target {
        Ok(())
    } else {
        Err(AutolykosError::InvalidPow {
            hit: hit.to_string(),
            target: target.to_string(),
        })
    }
}

/// Attempt to find a valid nonce for a v2 PoW puzzle.
///
/// Iterates `batch_size` nonces starting from `start_nonce`.
/// Returns `Some(nonce)` if a valid solution is found, `None` otherwise.
pub fn find_nonce(
    msg: &[u8; 32],
    target: &BigUint,
    height: u32,
    start_nonce: u64,
    batch_size: u64,
) -> Option<[u8; 8]> {
    let h = height_bytes(height);
    let n = calc_n(2, height);

    for offset in 0..batch_size {
        let nonce_val = start_nonce.wrapping_add(offset);
        let nonce = nonce_val.to_be_bytes();
        let hit = hit_for_version2_for_message(msg, &nonce, &h, n);
        if hit < *target {
            return Some(nonce);
        }
    }
    None
}

/// Compute the PoW hit for a version-2 header.
///
/// This implements `hitForVersion2ForMessage` from the Scala reference.
pub fn hit_for_version2(header: &Header) -> BigUint {
    let msg = msg_by_header(header);
    let nonce = &header.pow_solution.nonce;
    let h = height_bytes(header.height);
    let n = calc_n(header.version, header.height);

    hit_for_version2_for_message(&msg, nonce, &h, n)
}

/// Calculate the table size `N` based on version and height.
///
/// For v1, always returns `N_BASE`. For v2+, N increases by 5% every
/// `INCREASE_PERIOD_FOR_N` blocks starting at `INCREASE_START`.
pub fn calc_n(version: u8, header_height: u32) -> u32 {
    if version == 1 {
        return N_BASE;
    }

    let height = header_height.min(N_INCREASEMENT_HEIGHT_MAX);
    if height < INCREASE_START {
        return N_BASE;
    }

    let iters_number = ((height - INCREASE_START) / INCREASE_PERIOD_FOR_N + 1) as usize;
    let mut step = N_BASE as u64;
    for _ in 0..iters_number {
        step = step / 100 * 105;
    }
    step as u32
}

/// Generate `K` (32) indexes from a seed, each in the range `[0, n)`.
///
/// Implements `genIndexes` from the Scala reference.
pub fn gen_indexes(seed: &[u8], n: u32) -> Vec<u32> {
    let hash = blake2b256(seed);
    // extendedHash = hash ++ hash.take(3) => 35 bytes total
    let mut extended_hash = Vec::with_capacity(35);
    extended_hash.extend_from_slice(&hash);
    extended_hash.extend_from_slice(&hash[..3]);

    let n_big = BigUint::from(n);

    (0..K)
        .map(|i| {
            let slice = &extended_hash[i..i + 4];
            let val = BigUint::from_bytes_be(slice);
            let idx = val % &n_big;
            // idx fits in u32 since n is u32
            idx.to_u32_digits()
                .first()
                .copied()
                .unwrap_or(0)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute the PoW target: `q / decode_compact_bits(n_bits)`.
pub fn get_b(n_bits: u64) -> BigUint {
    let difficulty = decode_compact_bits(n_bits);
    if difficulty.is_zero() {
        return BigUint::ZERO;
    }
    &*Q / &difficulty
}

/// Compute the header message: `blake2b256(serialize_header_without_pow(header))`.
pub fn msg_by_header(header: &Header) -> [u8; 32] {
    let bytes = serialize_header_without_pow(header);
    blake2b256(&bytes)
}

/// Convert a height to a 4-byte big-endian byte array.
pub fn height_bytes(height: u32) -> [u8; 4] {
    height.to_be_bytes()
}

/// The core v2 hit computation.
///
/// Implements `hitForVersion2ForMessage` from the Scala reference:
/// 1. Compute `prei8 = hash(msg || nonce).takeRight(8)` as unsigned big-endian integer
/// 2. Compute `i = asUnsignedByteArray(4, prei8 mod N)`
/// 3. Compute `f = Blake2b256(i || h || M).drop(1)` (31 bytes)
/// 4. Compute `seed = f || msg || nonce`
/// 5. Compute `indexes = genIndexes(seed, N)`
/// 6. For each index, compute `genElement(version=2, msg, indexBytes, heightBytes)`
/// 7. Sum all elements -> `f2`
/// 8. Pad `f2` to 32 bytes -> `hash(f2_bytes)` -> unsigned big-endian = hit
pub fn hit_for_version2_for_message(
    msg: &[u8; 32],
    nonce: &[u8; 8],
    h: &[u8; 4],
    n: u32,
) -> BigUint {
    // Step 1: prei8 = fromUnsignedByteArray(hash(msg ++ nonce).takeRight(8))
    let mut concat1 = Vec::with_capacity(40);
    concat1.extend_from_slice(msg);
    concat1.extend_from_slice(nonce);
    let hash1 = blake2b256(&concat1);
    let prei8 = BigUint::from_bytes_be(&hash1[24..32]); // takeRight(8)

    // Step 2: i = asUnsignedByteArray(4, prei8 mod N)
    let n_big = BigUint::from(n);
    let i_val = prei8 % &n_big;
    let i_bytes = pad_to_n_bytes(&i_val, 4);

    // Step 3: f = Blake2b256(i ++ h ++ M).drop(1) => last 31 bytes
    let mut concat2 = Vec::with_capacity(4 + 4 + M.len());
    concat2.extend_from_slice(&i_bytes);
    concat2.extend_from_slice(h);
    concat2.extend_from_slice(&M);
    let hash2 = blake2b256(&concat2);
    let f = &hash2[1..]; // drop(1) = 31 bytes

    // Step 4: seed = f ++ msg ++ nonce
    let mut seed = Vec::with_capacity(31 + 32 + 8);
    seed.extend_from_slice(f);
    seed.extend_from_slice(msg);
    seed.extend_from_slice(nonce);

    // Step 5: indexes = genIndexes(seed, N)
    let indexes = gen_indexes(&seed, n);

    // Step 6: compute elements and sum
    let f2: BigUint = indexes
        .iter()
        .map(|&idx| gen_element(&idx.to_be_bytes(), h))
        .fold(BigUint::ZERO, |acc, elem| acc + elem);

    // Step 7: pad f2 to 32 bytes, then hash
    let f2_bytes = pad_to_n_bytes(&f2, 32);
    let ha = blake2b256(&f2_bytes);

    // Step 8: interpret hash as unsigned big-endian
    BigUint::from_bytes_be(&ha)
}

/// Generate a single element for v2.
///
/// `genElement(version=2, msg, pk=null, w=null, indexBytes, heightBytes)`:
/// `hash(indexBytes ++ heightBytes ++ M).drop(1)` interpreted as unsigned big-endian.
fn gen_element(index_bytes: &[u8; 4], height_bytes: &[u8; 4]) -> BigUint {
    let mut data = Vec::with_capacity(4 + 4 + M.len());
    data.extend_from_slice(index_bytes);
    data.extend_from_slice(height_bytes);
    data.extend_from_slice(&M);
    let hash = blake2b256(&data);
    // .drop(1) = remove first byte, take last 31 bytes
    BigUint::from_bytes_be(&hash[1..])
}

/// Pad a `BigUint` to exactly `n` bytes in big-endian unsigned form.
///
/// This matches `BigIntegers.asUnsignedByteArray(n, value)` from Bouncy Castle.
fn pad_to_n_bytes(value: &BigUint, n: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.len() >= n {
        // Take the least significant n bytes (rightmost).
        bytes[bytes.len() - n..].to_vec()
    } else {
        // Pad with leading zeros.
        let mut padded = vec![0u8; n - bytes.len()];
        padded.extend_from_slice(&bytes);
        padded
    }
}

/// Compute Blake2b-256 hash.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn m_constant_size() {
        assert_eq!(M.len(), 8192);
    }

    #[test]
    fn m_constant_first_bytes() {
        assert_eq!(&M[0..8], &[0u8; 8]);
        assert_eq!(&M[8..16], &[0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn calc_n_base() {
        assert_eq!(calc_n(2, 0), N_BASE);
        assert_eq!(calc_n(2, 500_000), N_BASE);
        assert_eq!(calc_n(1, 1_000_000), N_BASE); // v1 always NBase
    }

    #[test]
    fn calc_n_increases() {
        let n_at_start = calc_n(2, INCREASE_START);
        assert!(n_at_start > N_BASE);
    }

    #[test]
    fn gen_indexes_count() {
        let seed = [0u8; 32];
        let indexes = gen_indexes(&seed, 1_000_000);
        assert_eq!(indexes.len(), K);
    }

    #[test]
    fn gen_indexes_within_range() {
        let seed = [0xAB; 32];
        let n = 1_000_000u32;
        let indexes = gen_indexes(&seed, n);
        for idx in &indexes {
            assert!(*idx < n);
        }
    }

    #[test]
    fn q_constant_correct() {
        let expected = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();
        assert_eq!(*Q, expected);
    }

    #[test]
    fn test_get_b_nonzero() {
        // 100734821 is a real nBits value from Ergo mainnet
        let b = get_b(100_734_821);
        assert!(!b.is_zero(), "get_b should return nonzero for real nBits");
    }

    #[test]
    fn test_msg_by_header_deterministic() {
        use ergo_types::header::Header;
        let mut header = Header::default_for_test();
        header.version = 2;
        header.height = 500_000;
        header.timestamp = 1_600_000_000_000;

        let msg1 = msg_by_header(&header);
        let msg2 = msg_by_header(&header);
        assert_eq!(msg1, msg2, "msg_by_header should be deterministic");
    }

    #[test]
    fn test_height_bytes_encoding() {
        assert_eq!(height_bytes(1000), [0, 0, 3, 232]);
    }

    #[test]
    fn test_find_nonce_with_easy_target() {
        // Use Q as target (very easy — nearly any hit will be below it)
        let msg = [0xABu8; 32];
        let target = Q.clone();
        let result = find_nonce(&msg, &target, 100_000, 0, 100);
        assert!(result.is_some(), "find_nonce should find a solution with Q as target");
    }

    #[test]
    fn test_find_nonce_no_solution() {
        // Target of 1 is impossibly hard — no hit will be < 1
        let msg = [0xCDu8; 32];
        let target = BigUint::from(1u32);
        let result = find_nonce(&msg, &target, 100_000, 0, 10);
        assert!(result.is_none(), "find_nonce should return None for impossibly hard target");
    }
}
