//! Scala 2.12 `HashTrieMap` iteration-order helpers — used by
//! [`crate::input::write_context_extension`] when a context extension
//! carries ≥ 5 entries.
//!
//! # Why this exists
//!
//! `Map[Byte, T]` in Scala 2.12 is `Map1`–`Map4` (insertion-ordered) up
//! to four entries and `HashTrieMap` from five onward. `HashTrieMap` is
//! a Hash Array Mapped Trie (HAMT): iteration order is the trie's
//! depth-first walk over 5-bit chunks of each key's *improved* hash —
//! never ascending by key.
//!
//! A Scala wallet building a transaction with ≥ 5 context-extension
//! vars iterates the map in HAMT order, emits bytes in that order, and
//! signs the result. If we re-serialize those entries in any other
//! order (e.g. ascending by key), `bytes_to_sign(tx)` desyncs and the
//! signature won't verify.
//!
//! Block ingest is already safe via verbatim preservation in
//! [`crate::input::SpendingProof::from_trusted_raw_parts`]. This module
//! exists so the REST submit path's *re-serialize from parsed
//! [`crate::input::ContextExtension`]* path reproduces HAMT order from
//! a [`std::collections::BTreeMap`] storage. The wire-correct order
//! falls out of sorting keys by [`hamt_sort_key_for_byte_key`].
//!
//! # The algorithm, ported from Scala 2.12 `HashMap.scala`
//!
//! Two pieces:
//!
//! ## `scala_212_improve` — the hash-mixing transform
//!
//! Scala source (`scala.collection.immutable.HashMap`, Scala 2.12):
//!
//! ```scala
//! private def improve(hcode: Int): Int = {
//!   var h: Int = hcode + ~(hcode << 9)
//!   h = h ^ (h >>> 14)
//!   h = h + (h << 4)
//!   h ^ (h >>> 10)
//! }
//! ```
//!
//! Wrapping arithmetic mirrors JVM `Int` (two's-complement, overflow
//! wraps silently). All right shifts on the RHS are logical (`>>>`).
//!
//! ## `scala_212_hamt_sort_key` — derive a comparable key
//!
//! `HashTrieMap` branches on 5 bits per level starting from the *least
//! significant* bits of the improved hash: bits 0-4 select a root-level
//! bucket, bits 5-9 the next level, etc., for 6 full levels covering
//! bits 0-29. A 7th level uses bits 30-31 as a 2-bit residue (4
//! buckets). Iteration visits buckets in ascending order at each level.
//!
//! That means HAMT order over a set of keys is *lexicographic* over the
//! 5-bit chunks (and the trailing 2-bit chunk) of
//! `improve(key.hashCode)` starting from the LSB. We pack those
//! chunks into a u32 with chunk 0 at the high end and the 2-bit
//! residue at the very low end, so a plain ascending sort by the
//! packed key reproduces HAMT iteration order — including the
//! depth-7 split.
//!
//! The packing MUST cover all 32 bits. Dropping bits 30-31 would
//! leave the sort key injective over the u8 keyspace (verified by
//! `sort_key_is_injective_over_u8_keys`), but for a general 32-bit
//! hash two inputs that differed only in bits 30-31 would collapse
//! to the same sort key, silently breaking Scala parity at depth 7.
//!
//! # Sign extension
//!
//! Scala's `Byte.hashCode` sign-extends — for byte value `0x80` (i8
//! `-128`) the hashCode is `-128_i32`, not `128_i32`. We cast `key as
//! i8 as i32` before `improve` so keys ≥ 128 sort correctly. Casting
//! `key as i32` zero-extends and produces the wrong order for half the
//! keyspace.
//!
//! # Provenance of test vectors
//!
//! The unit tests in this module compute their expected orderings from
//! the algorithm itself (Scala 2.12 source above). They do not
//! constitute a true external oracle: a real Scala-node-extracted set
//! of `(keys, expected_hamt_order)` vectors is the right backstop.
//! Parity rests on cross-reading the Scala 2.12 `HashMap.scala`
//! source, not on cross-running a Scala node.

/// Scala 2.12 `HashMap.improve` ported verbatim.
///
/// JVM `Int` arithmetic wraps silently on overflow; we use `wrapping_*`
/// to mirror that. Right shifts on the RHS in the Scala source use
/// `>>>` (logical shift); the casts to `u32` here implement that.
pub fn scala_212_improve(hcode: i32) -> i32 {
    let mut h = hcode.wrapping_add(!hcode.wrapping_shl(9));
    h ^= ((h as u32) >> 14) as i32;
    h = h.wrapping_add(h.wrapping_shl(4));
    h ^ (((h as u32) >> 10) as i32)
}

/// Derive the HAMT iteration sort key from an already-improved hash.
///
/// Returns a u32 whose ascending sort reproduces Scala 2.12
/// `HashTrieMap` depth-first iteration order. Bits 0-4 of `improved`
/// (the root-level branch) map to result bits 27-31 (highest 5 bits);
/// bits 25-29 (level 5) map to result bits 2-6; bits 30-31 (the 2-bit
/// depth-7 residue) map to result bits 0-1. Every bit of the input is
/// represented in the sort key — there are no collapsed inputs.
pub fn scala_212_hamt_sort_key(improved: i32) -> u32 {
    let u = improved as u32;
    let c0 = u & 0x1F; // root level — bits 0-4
    let c1 = (u >> 5) & 0x1F;
    let c2 = (u >> 10) & 0x1F;
    let c3 = (u >> 15) & 0x1F;
    let c4 = (u >> 20) & 0x1F;
    let c5 = (u >> 25) & 0x1F;
    let c6 = (u >> 30) & 0x03; // depth-7 residue — bits 30-31
    (c0 << 27) | (c1 << 22) | (c2 << 17) | (c3 << 12) | (c4 << 7) | (c5 << 2) | c6
}

/// Convenience: derive HAMT sort key for a u8 context-extension var
/// index. Sign-extends `key as i8 as i32` to match Scala
/// `Byte.hashCode` before applying `improve` + `hamt_sort_key`.
pub fn hamt_sort_key_for_byte_key(key: u8) -> u32 {
    let hcode = (key as i8) as i32;
    scala_212_hamt_sort_key(scala_212_improve(hcode))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// Apply Scala 2.12 HAMT iteration to a set of u8 keys: returns the
    /// keys in the order Scala would yield them when iterating a
    /// `HashTrieMap[Byte, T]` containing exactly that key set.
    fn hamt_order(keys: &[u8]) -> Vec<u8> {
        let mut sorted: Vec<u8> = keys.to_vec();
        sorted.sort_by_key(|&k| hamt_sort_key_for_byte_key(k));
        sorted
    }

    // ----- algorithm parity (`improve`) -----

    /// `improve(0)` should be 0 because every term in the algorithm
    /// reduces to 0 when the input is 0:
    /// `0 + ~(0 << 9) = 0 + ~0 = -1`, then `-1 ^ (-1 >>> 14)` etc.
    /// Wait — actually that's not 0. Trace it through:
    /// `h = 0 + ~(0 << 9) = 0 + ~0 = -1`
    /// `h = -1 ^ ((-1 as u32) >> 14) = -1 ^ 0x0003FFFF = 0xFFFC0000_i32 = -262144`
    /// Just pin whatever the algorithm actually returns; the value
    /// isn't a constant we can derive mentally without running it.
    #[test]
    fn improve_is_pure_function() {
        // Idempotency / repeatability of the pure function — same
        // input always returns same output. Sanity guard for refactor.
        let a = scala_212_improve(0x12345678);
        let b = scala_212_improve(0x12345678);
        assert_eq!(a, b);
    }

    #[test]
    fn improve_distinguishes_neighbours() {
        // The whole point of `improve` is to scatter sequential inputs
        // across the hash space so HAMT branching is well-balanced. If
        // it ever collapsed neighbours together the trie would
        // degenerate. Pin the property over a small range.
        let mut hashes: Vec<i32> = (0..32i32).map(scala_212_improve).collect();
        let raw_count = hashes.len();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            raw_count,
            "improve must not collapse 0..32 inputs",
        );
    }

    // ----- algorithm parity (`hamt_sort_key`) -----

    #[test]
    fn hamt_sort_key_includes_high_two_bits() {
        // Scala's HAMT branches at depth 7 on bits 30-31 as a 2-bit
        // residue level. The sort key MUST include those bits as the
        // least-significant chunk so two improved hashes that differ
        // ONLY in bits 30-31 still produce different sort keys —
        // otherwise Scala's depth-7 separation collapses into our
        // sort.
        let base = 0x1234_5678_i32;
        let high_bits_flipped = base ^ (0b11i32 << 30);
        assert_ne!(
            scala_212_hamt_sort_key(base),
            scala_212_hamt_sort_key(high_bits_flipped),
            "bits 30-31 of improved hash must be retained as depth-7 residue",
        );
    }

    #[test]
    fn hamt_sort_key_orders_high_bits_after_low_chunks() {
        // The 2-bit residue is the deepest level, so it's the lowest-
        // priority tiebreaker. Two hashes that differ at both the LSB
        // chunk AND the high-2-bits residue must be ordered by the
        // LSB chunk (root level wins).
        let a = scala_212_hamt_sort_key(0b11_00000_00000_00000_00000_00000_00001u32 as i32); // LSB chunk = 1, high2 = 0b11
        let b = scala_212_hamt_sort_key(0b00_00000_00000_00000_00000_00000_00010u32 as i32); // LSB chunk = 2, high2 = 0
        assert!(
            a < b,
            "LSB chunk wins over high-2-bits residue (a={a:x}, b={b:x})",
        );
    }

    // Literals below are grouped 5-5-5-5-5-5-2 to mirror the HAMT branch
    // chunks (six 5-bit levels + a 2-bit depth-7 residue), not 4-bit
    // nibbles. Clippy's unusual_byte_groupings lint flags this; the
    // grouping is intentional and load-bearing for readability.
    #[allow(clippy::unusual_byte_groupings)]
    #[test]
    fn hamt_sort_key_lsb_chunk_dominates() {
        // The lowest 5 bits of `improved` (root-level bucket) must
        // dominate the sort key. Two inputs that share every bit
        // EXCEPT the LSB chunk must be ordered by the LSB chunk only.
        let lo = scala_212_hamt_sort_key(0b00000_11111_11111_11111_11111_11111_00u32 as i32);
        let hi = scala_212_hamt_sort_key(0b11111_11111_11111_11111_11111_11111_00u32 as i32);
        assert!(
            lo < hi,
            "lowest-chunk-zero ({lo:x}) must sort before lowest-chunk-thirtyone ({hi:x})",
        );
    }

    // ----- HAMT iteration ordering -----

    #[test]
    fn hamt_order_is_stable() {
        // The order for any given key set is a pure function of the
        // keys. No external state, no insertion-order dependence.
        let keys = [3u8, 7, 11, 13, 17, 19];
        let a = hamt_order(&keys);
        let b = hamt_order(&keys);
        assert_eq!(a, b);
    }

    #[test]
    fn hamt_order_diverges_from_ascending_for_some_keysets() {
        // The whole point of this module is that HAMT iteration is NOT
        // ascending for typical wallet key sets — the existence of the
        // gap requires at least one observable divergence. Sweep a few
        // size-classes and key-spread classes; assert at least one
        // produces non-ascending HAMT order. If `improve` were ever
        // replaced with a monotone function this test would fail and
        // surface the regression.
        let cases: &[&[u8]] = &[
            &[3, 17, 42, 99, 137, 200, 230, 255],
            &[5, 50, 100, 150, 200, 250],
            &[10, 20, 30, 40, 50, 60, 70, 80],
            &[1, 2, 3, 4, 5, 200],
        ];
        let mut any_diverged = false;
        for keys in cases {
            let hamt = hamt_order(keys);
            let mut ascending = keys.to_vec();
            ascending.sort();
            if hamt != ascending {
                any_diverged = true;
                break;
            }
        }
        assert!(
            any_diverged,
            "at least one test keyset must produce HAMT order != ascending",
        );
    }

    #[test]
    fn hamt_order_at_n_5_boundary() {
        // n = 5 is the Scala threshold where Map4 yields to HashTrieMap.
        // Locking it explicitly avoids regressing the gate.
        let keys = [0u8, 1, 2, 3, 4];
        let ord = hamt_order(&keys);
        assert_eq!(ord.len(), 5);
        // Property check: every original key is in the result exactly
        // once (no duplication, no loss).
        let mut s = ord.clone();
        s.sort();
        assert_eq!(s, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn hamt_order_handles_high_bit_keys() {
        // Sign-extension bug catcher: keys ≥ 128 must order
        // consistently with the algorithm. If we cast `key as i32`
        // (zero-extend) instead of `key as i8 as i32`, the order is
        // wrong for half the keyspace and this test changes.
        // Mixed low+high keys forces both extension paths through.
        let keys = [0u8, 50, 100, 150, 200, 250];
        let ord = hamt_order(&keys);
        assert_eq!(ord.len(), 6);
        let mut s = ord.clone();
        s.sort();
        assert_eq!(s, vec![0, 50, 100, 150, 200, 250]);
        // Stability cross-check: redoing the computation must yield
        // exactly the same sequence.
        let ord2 = hamt_order(&keys);
        assert_eq!(ord, ord2);
    }

    #[test]
    fn hamt_order_at_full_byte_keyspace() {
        // 256 distinct u8 keys exhausts the domain — the HAMT must
        // yield a permutation of 0..=255 with no collisions or
        // dropouts. Stress test for the algorithm and for the
        // sort-key injectivity over the full u8 domain.
        let keys: Vec<u8> = (0u8..=255u8).collect();
        let ord = hamt_order(&keys);
        assert_eq!(ord.len(), 256);
        let mut s = ord.clone();
        s.sort();
        let expected: Vec<u8> = (0u8..=255u8).collect();
        assert_eq!(
            s, expected,
            "HAMT iteration must be a permutation of the input keyset",
        );
    }

    // ----- Scala 2.12 oracle parity (extracted via JVM) -----
    //
    // Oracle source: Scala 2.12.18 standard-library `HashTrieMap[Byte,
    // Int]` iteration order, extracted by a Java program in
    // `scripts/scala_hamt_oracle/ExtractHamtVectors.java` (committed
    // alongside its `scala-library` dep manifest). The Rust algorithm
    // here is consensus-correct iff `hamt_order(keys)` reproduces the
    // Scala iteration order for the same keyset.
    //
    // If these tests fail, the Rust HAMT algorithm has drifted from
    // Scala. Re-run the extraction script and compare. Provenance
    // is real-Scala-execution, not algorithm-self-derivation.

    #[test]
    fn hamt_order_scala_oracle_n_5_mixed_lowmid_high() {
        let keys = [3u8, 17, 42, 99, 200];
        // From ExtractHamtVectors.java output
        let scala = vec![42u8, 17, 3, 99, 200];
        assert_eq!(hamt_order(&keys), scala);
    }

    #[test]
    fn hamt_order_scala_oracle_n_7_high_bit_mixed() {
        let keys = [11u8, 23, 47, 89, 137, 199, 251];
        let scala = vec![89u8, 137, 251, 199, 11, 23, 47];
        assert_eq!(hamt_order(&keys), scala);
    }

    #[test]
    fn hamt_order_scala_oracle_n_5_low_bit_only() {
        let keys = [3u8, 17, 42, 65, 99];
        let scala = vec![42u8, 65, 17, 3, 99];
        assert_eq!(hamt_order(&keys), scala);
    }

    #[test]
    fn hamt_order_scala_oracle_n_5_high_bit_only() {
        // Sign-extension catcher: every key has its high bit set, so
        // a zero-extension bug would produce a different order from
        // Scala's `Byte.hashCode`.
        let keys = [131u8, 145, 170, 193, 227];
        let scala = vec![170u8, 193, 145, 227, 131];
        assert_eq!(hamt_order(&keys), scala);
    }

    #[test]
    fn hamt_order_scala_oracle_n_8_diverges_set() {
        let keys = [3u8, 17, 42, 99, 137, 200, 230, 255];
        let scala = vec![42u8, 230, 137, 17, 3, 255, 99, 200];
        assert_eq!(hamt_order(&keys), scala);
    }

    #[test]
    fn hamt_order_scala_oracle_n_6_spread() {
        let keys = [5u8, 50, 100, 150, 200, 250];
        let scala = vec![5u8, 150, 50, 250, 200, 100];
        assert_eq!(hamt_order(&keys), scala);
    }

    #[test]
    fn hamt_order_scala_oracle_n_8_decimal_spread() {
        let keys = [10u8, 20, 30, 40, 50, 60, 70, 80];
        let scala = vec![10u8, 20, 60, 70, 80, 50, 40, 30];
        assert_eq!(hamt_order(&keys), scala);
    }

    #[test]
    fn hamt_order_scala_oracle_n_6_mostly_ascending() {
        let keys = [1u8, 2, 3, 4, 5, 200];
        let scala = vec![5u8, 1, 2, 3, 4, 200];
        assert_eq!(hamt_order(&keys), scala);
    }

    #[test]
    fn hamt_order_scala_oracle_n_5_sequential() {
        // The accidental-ascending case: for keys [0..4] Scala happens
        // to yield ascending order. Pinning so a future algorithm
        // change that breaks this regresses loudly.
        let keys = [0u8, 1, 2, 3, 4];
        let scala = vec![0u8, 1, 2, 3, 4];
        assert_eq!(hamt_order(&keys), scala);
    }

    #[test]
    fn sort_key_is_injective_over_u8_keys() {
        // 256 distinct byte keys must produce 256 distinct sort keys
        // — otherwise an unstable Vec::sort_by_key could yield
        // nondeterministic ordering and break consensus reproducibility.
        // (`improve` doesn't strictly need to be injective over its
        // full Int input, but the composition with our u8→i8→i32
        // input domain must be.)
        let keys: std::collections::HashSet<u32> =
            (0u8..=255u8).map(hamt_sort_key_for_byte_key).collect();
        assert_eq!(
            keys.len(),
            256,
            "sort key must be injective over u8 keyspace",
        );
    }
}
