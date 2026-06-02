use num_bigint::BigUint;

use super::common::{
    biguint_to_32bytes, blake2b256, calc_n, gen_indexes_k, to_big_int, AUTOLYKOS_K, M_BYTES,
};

/// Compute the Autolykos v2 PoW hit for a header. This is the
/// header-validation specialization of [`hit_for_v2_pow`]: `k = 32`
/// indices and `h = height` as 4-byte big-endian. Keeping it a thin
/// wrapper means the ~9k-header mainnet corpus in `tests/pow_mainnet.rs`
/// exercises the same general code path `SGlobal.powHit` uses.
pub fn hit_for_v2(msg: &[u8; 32], nonce: &[u8; 8], height: u32, n: u32) -> BigUint {
    hit_for_v2_pow(AUTOLYKOS_K, msg, nonce, &height.to_be_bytes(), n)
}

/// General Autolykos v2 PoW hit, matching Scala v6.0.2
/// `Autolykos2PowValidation.hitForVersion2ForMessage(k, msg, nonce, h, N)`
/// — the computation behind `SGlobal.powHit`. `k` is the index count
/// (callers enforce Scala's `2 <= k <= 32`); `msg`, `nonce`, `h` are
/// arbitrary byte strings; `n` is the table size N.
///
/// 1. prei8 = last 8 bytes of Blake2b256(msg ++ nonce), as BigUint
/// 2. i = prei8 mod N, as 4-byte big-endian
/// 3. f = Blake2b256(i ++ h ++ M).drop(1) — 31 bytes
/// 4. seed = f ++ msg ++ nonce
/// 5. indexes = genIndexes(k, seed, N)
/// 6. for each index j: elem_j = BigUint(Blake2b256(j_bytes ++ h ++ M).drop(1))
/// 7. f2 = sum of all elem_j
/// 8. hit = BigUint(Blake2b256(f2 as 32-byte big-endian))
pub fn hit_for_v2_pow(k: usize, msg: &[u8], nonce: &[u8], h: &[u8], n: u32) -> BigUint {
    // Step 1: prei8 = last 8 bytes of hash(msg ++ nonce)
    let mut msg_nonce = Vec::with_capacity(msg.len() + nonce.len());
    msg_nonce.extend_from_slice(msg);
    msg_nonce.extend_from_slice(nonce);
    let hash1 = blake2b256(&msg_nonce);
    let prei8 = BigUint::from_bytes_be(&hash1[24..32]); // takeRight(8)

    // Step 2: i = prei8 mod N, as 4-byte big-endian
    let i = &prei8 % n;
    let i_bytes = uint_to_4bytes(&i);

    // Step 3: f = Blake2b256(i ++ h ++ M).drop(1) — 31 bytes
    let f = gen_element_hash(&i_bytes, h);

    // Step 4: seed = f ++ msg ++ nonce
    let mut seed = Vec::with_capacity(31 + msg.len() + nonce.len());
    seed.extend_from_slice(&f);
    seed.extend_from_slice(msg);
    seed.extend_from_slice(nonce);

    // Steps 5-6: generate k indices and sum their elements
    let indexes = gen_indexes_k(&seed, k, n);
    let mut f2 = BigUint::ZERO;
    for idx in indexes {
        let idx_bytes = idx.to_be_bytes();
        let elem_bytes = gen_element_hash(&idx_bytes, h);
        f2 += to_big_int(&elem_bytes);
    }

    // Step 7-8: final hash of f2 as 32-byte big-endian
    let f2_bytes = biguint_to_32bytes(&f2);
    let final_hash = blake2b256(&f2_bytes);
    to_big_int(&final_hash)
}

/// Compute v2 genElement: Blake2b256(index_bytes ++ h ++ M).drop(1).
/// Returns 31 bytes (the hash with first byte dropped). `h` is the
/// header height as 4-byte big-endian on the PoW-validation path, or the
/// arbitrary `h` argument for `SGlobal.powHit`.
fn gen_element_hash(index_bytes: &[u8; 4], h: &[u8]) -> [u8; 31] {
    let mut input = Vec::with_capacity(4 + h.len() + M_BYTES.len());
    input.extend_from_slice(index_bytes);
    input.extend_from_slice(h);
    input.extend_from_slice(&M_BYTES);
    let hash = blake2b256(&input);
    let mut result = [0u8; 31];
    result.copy_from_slice(&hash[1..]); // drop(1) = takeRight(31)
    result
}

/// Convert BigUint to 4-byte big-endian, matching Scala
/// `BigIntegers.asUnsignedByteArray(4, value)`.
fn uint_to_4bytes(val: &BigUint) -> [u8; 4] {
    let bytes = val.to_bytes_be();
    let mut out = [0u8; 4];
    if bytes.len() >= 4 {
        out.copy_from_slice(&bytes[bytes.len() - 4..]);
    } else {
        out[4 - bytes.len()..].copy_from_slice(&bytes);
    }
    out
}

/// Full v2 PoW check: compute hit and compare against target.
/// `msg` = Blake2b256(header_bytes_without_pow).
/// `target` = q / decode_compact_bits(nBits).
pub fn check_pow_v2(
    msg: &[u8; 32],
    nonce: &[u8; 8],
    height: u32,
    version: u8,
    target: &BigUint,
) -> bool {
    let n = calc_n(version, height);
    let hit = hit_for_v2(msg, nonce, height, n);
    hit < *target
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    /// Byte-order regression guard for `uint_to_4bytes`. The full v2
    /// hit pipeline is exercised by the ~9k-header mainnet corpus in
    /// `tests/pow_mainnet.rs`; this only pins the corner cases (zero,
    /// small, byte-boundary, full-width) so a mistake here surfaces
    /// instantly without needing a corpus run to bisect.
    #[test]
    fn uint_to_4bytes_pads_be_for_short_values_and_passes_full_width() {
        assert_eq!(uint_to_4bytes(&BigUint::from(0u32)), [0, 0, 0, 0]);
        assert_eq!(uint_to_4bytes(&BigUint::from(1u32)), [0, 0, 0, 1]);
        assert_eq!(uint_to_4bytes(&BigUint::from(256u32)), [0, 0, 1, 0]);
        assert_eq!(
            uint_to_4bytes(&BigUint::from(0xDEADBEEFu32)),
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    // ----- properties -----

    proptest::proptest! {
        /// Algebraic property: for every `v: u32`,
        /// `u32::from_be_bytes(uint_to_4bytes(BigUint::from(v))) == v`.
        ///
        /// This pins the big-endian byte order + 4-byte width invariant
        /// across the entire u32 domain, complementing the corner-case
        /// unit test above (zero, 1, byte-boundary, full-width) by
        /// catching any width/order regression on a random sample.
        #[test]
        fn proptest_uint_to_4bytes_u32_round_trips(v in proptest::prelude::any::<u32>()) {
            let bytes = uint_to_4bytes(&BigUint::from(v));
            let decoded = u32::from_be_bytes(bytes);
            proptest::prop_assert_eq!(decoded, v);
        }
    }

    // ----- oracle parity -----

    /// Sigma 6.0 `SGlobal.powHit` known-answer vector from
    /// sigmastate-interpreter v6.0.2 `BasicOpsTests.scala` ("powHit
    /// evaluation", asserted through both `SigmaDsl.powHit` and a
    /// `MethodCall`). The 7-byte `msg` exercises the arbitrary-length
    /// generalization that the 32-byte-msg mainnet corpus cannot.
    #[test]
    fn hit_for_v2_pow_matches_sigmastate_v6_0_2_kat() {
        let msg = [0x0a, 0x10, 0x1b, 0x8c, 0x6a, 0x4f, 0x2e];
        let nonce = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c];
        let h = [0x00, 0x00, 0x00, 0x00];
        let expected: BigUint =
            "326674862673836209462483453386286740270338859283019276168539876024851191344"
                .parse()
                .unwrap();
        assert_eq!(hit_for_v2_pow(32, &msg, &nonce, &h, 1_048_576), expected);
    }

    /// Real-mainnet-header hit (Ergo Scala node `AutolykosPowSchemeSpec`,
    /// height 614400) driven through the general `hit_for_v2_pow` with
    /// `h = Ints.toByteArray(614400)`. Confirms the production shape
    /// (32-byte msg, k=32) independently of the corpus.
    #[test]
    fn hit_for_v2_pow_matches_ergo_node_mainnet_614400() {
        let msg = hex::decode("548c3e602a8f36f8f2738f5f643b02425038044d98543a51cabaa9785e7e864f")
            .unwrap();
        let nonce = hex::decode("0000000000003105").unwrap();
        let h = 614_400u32.to_be_bytes();
        let expected = BigUint::from_bytes_be(
            &hex::decode("0002fcb113fe65e5754959872dfdbffea0489bf830beb4961ddc0e9e66a1412a")
                .unwrap(),
        );
        assert_eq!(hit_for_v2_pow(32, &msg, &nonce, &h, 70_464_240), expected);
    }
}
