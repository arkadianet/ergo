//! The Poseidon2-BabyBear width-24 permutation used by the stock RISC0
//! verifier profile's Merkle commitments (EIP-0045 `verifyStark`).
//!
//! Faithful port of risc0-zkp 1.2.6 `core::hash::poseidon2::poseidon2_mix`:
//! initial external linear layer, [`ROUNDS_HALF_FULL`] full rounds (constants,
//! x^7 s-box on every cell, external matrix), [`ROUNDS_PARTIAL`] partial rounds
//! (single constant, x^7 on cell 0, internal matrix), [`ROUNDS_HALF_FULL`] full
//! rounds. The external matrix multiply uses the 4x4-circulant decomposition of
//! the Poseidon2 paper (appendix B); the internal matrix has all-ones
//! off-diagonal with `M_INT_DIAG` on the diagonal. Constants come from
//! [`crate::poseidon2_constants`], extracted programmatically from risc0-zkp.
//!
//! Correctness is pinned by permutation Known Answer Tests taken from risc0-zkp
//! itself (`test-vectors/ergo-stark/poseidon2_perm.tsv`, `_hash.tsv`).

use crate::baby_bear::BabyBear as F;
use crate::poseidon2_constants::CELLS;
use crate::poseidon2_constants::{M_INT_DIAG, ROUNDS_HALF_FULL, ROUNDS_PARTIAL, ROUND_CONSTANTS};

/// Namespace for the Poseidon2-BabyBear sponge. Operates on canonical
/// [`crate::baby_bear::BabyBear`] values held in fixed-width arrays.
pub struct Poseidon2;

impl Poseidon2 {
    /// Permutation/sponge width in field cells.
    pub const CELLS: usize = CELLS;
    /// Digest length in field elements.
    pub const CELLS_OUT: usize = 8;
    /// Sponge rate in field elements.
    pub const CELLS_RATE: usize = 16;

    /// x^7 over BabyBear.
    #[inline]
    fn sbox(x: u32) -> u32 {
        let x2 = F::mul(x, x);
        let x4 = F::mul(x2, x2);
        F::mul(F::mul(x4, x2), x)
    }

    /// External (full-round) linear layer: a 4x4 circulant on each 4-cell block
    /// followed by the cross-block column-sum fold.
    fn multiply_by_m_ext(cells: &mut [u32; CELLS]) {
        let mut sum0 = 0u32;
        let mut sum1 = 0u32;
        let mut sum2 = 0u32;
        let mut sum3 = 0u32;
        let mut i = 0;
        while i < CELLS / 4 {
            let base = i * 4;
            let x0 = cells[base];
            let x1 = cells[base + 1];
            let x2 = cells[base + 2];
            let x3 = cells[base + 3];
            let t0 = F::add(x0, x1);
            let t1 = F::add(x2, x3);
            let t2 = F::add(F::mul(2, x1), t1);
            let t3 = F::add(F::mul(2, x3), t0);
            let t4 = F::add(F::mul(4, t1), t3);
            let t5 = F::add(F::mul(4, t0), t2);
            let out0 = F::add(t3, t5);
            let out1 = t5;
            let out2 = F::add(t2, t4);
            let out3 = t4;

            cells[base] = out0;
            cells[base + 1] = out1;
            cells[base + 2] = out2;
            cells[base + 3] = out3;
            sum0 = F::add(sum0, out0);
            sum1 = F::add(sum1, out1);
            sum2 = F::add(sum2, out2);
            sum3 = F::add(sum3, out3);
            i += 1;
        }
        i = 0;
        while i < CELLS / 4 {
            let base = i * 4;
            cells[base] = F::add(cells[base], sum0);
            cells[base + 1] = F::add(cells[base + 1], sum1);
            cells[base + 2] = F::add(cells[base + 2], sum2);
            cells[base + 3] = F::add(cells[base + 3], sum3);
            i += 1;
        }
    }

    /// Internal (partial-round) linear layer: all-ones off-diagonal with
    /// `M_INT_DIAG` on the diagonal.
    fn multiply_by_m_int(cells: &mut [u32; CELLS]) {
        let mut sum = 0u32;
        let mut i = 0;
        while i < CELLS {
            sum = F::add(sum, cells[i]);
            i += 1;
        }
        i = 0;
        while i < CELLS {
            cells[i] = F::add(sum, F::mul(M_INT_DIAG[i], cells[i]));
            i += 1;
        }
    }

    fn full_round(cells: &mut [u32; CELLS], round: usize) {
        let mut i = 0;
        while i < CELLS {
            cells[i] = Self::sbox(F::add(cells[i], ROUND_CONSTANTS[round * CELLS + i]));
            i += 1;
        }
        Self::multiply_by_m_ext(cells);
    }

    fn partial_round(cells: &mut [u32; CELLS], round: usize) {
        cells[0] = Self::sbox(F::add(cells[0], ROUND_CONSTANTS[round * CELLS]));
        Self::multiply_by_m_int(cells);
    }

    /// The raw sponge mixing function; permutes `cells` in place. Mirror of
    /// risc0-zkp `poseidon2_mix`.
    pub fn mix(cells: &mut [u32; CELLS]) {
        let mut round = 0;
        Self::multiply_by_m_ext(cells);
        let mut i = 0;
        while i < ROUNDS_HALF_FULL {
            Self::full_round(cells, round);
            round += 1;
            i += 1;
        }
        i = 0;
        while i < ROUNDS_PARTIAL {
            Self::partial_round(cells, round);
            round += 1;
            i += 1;
        }
        i = 0;
        while i < ROUNDS_HALF_FULL {
            Self::full_round(cells, round);
            round += 1;
            i += 1;
        }
    }

    /// Unpadded sponge hash — mirror of risc0-zkp `unpadded_hash`:
    /// overwrite-absorb [`Self::CELLS_RATE`] elements per block, permute,
    /// zero-pad the final partial block (also hashing an empty input as one zero
    /// block); the digest is the first [`Self::CELLS_OUT`] cells.
    ///
    /// NOTE (as upstream documents): collision resistance holds only among
    /// equal-length inputs.
    pub fn unpadded_hash(input: &[u32]) -> [u32; 8] {
        let mut state = [0u32; CELLS];
        let mut unmixed = 0usize;
        let mut i = 0;
        while i < input.len() {
            state[unmixed] = input[i];
            unmixed += 1;
            if unmixed == Self::CELLS_RATE {
                Self::mix(&mut state);
                unmixed = 0;
            }
            i += 1;
        }
        if unmixed != 0 || input.is_empty() {
            let mut j = unmixed;
            while j < Self::CELLS_RATE {
                state[j] = 0;
                j += 1;
            }
            Self::mix(&mut state);
        }
        let mut out = [0u32; 8];
        out.copy_from_slice(&state[0..Self::CELLS_OUT]);
        out
    }

    /// Merkle node compression — `unpadded_hash` of two 8-element digests
    /// (RISC0 `Poseidon2HashFn.hash_pair`). A pair is exactly one full rate
    /// block, so the state is built directly.
    pub fn hash_pair(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
        let mut state = [0u32; CELLS];
        let mut i = 0;
        while i < Self::CELLS_OUT {
            state[i] = a[i];
            state[Self::CELLS_OUT + i] = b[i];
            i += 1;
        }
        Self::mix(&mut state);
        let mut out = [0u32; 8];
        out.copy_from_slice(&state[0..Self::CELLS_OUT]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn parse_u32s(s: &str) -> Vec<u32> {
        if s.is_empty() {
            Vec::new()
        } else {
            s.split(',').map(|x| x.parse().unwrap()).collect()
        }
    }

    // ----- happy path -----

    #[test]
    fn zero_permutation_matches_embedded_kat() {
        // Pinned in the reference StarkPrimitiveAllocationSpec.
        let mut cells = [0u32; CELLS];
        Poseidon2::mix(&mut cells);
        assert_eq!(
            cells,
            [
                972705262, 946791486, 1172739502, 607725896, 1443562977, 10371933, 1256364390,
                832646779, 324608513, 1218088384, 1927362941, 1316083208, 1247749003, 494661501,
                219252024, 979706958, 417250331, 1789792672, 422984860, 1807101920, 1567038995,
                1949574701, 1240162431, 1775282439,
            ]
        );
    }

    // ----- round-trips -----

    #[test]
    fn hash_pair_equals_one_block_unpadded_hash() {
        let left: [u32; 8] = std::array::from_fn(|i| (i as u32) * 7919 + 17);
        let right: [u32; 8] = std::array::from_fn(|i| F::P - 1 - (i as u32) * 3571);
        let mut concat = Vec::with_capacity(16);
        concat.extend_from_slice(&left);
        concat.extend_from_slice(&right);
        assert_eq!(
            Poseidon2::hash_pair(&left, &right),
            Poseidon2::unpadded_hash(&concat)
        );
    }

    // ----- oracle parity -----

    #[test]
    fn permutation_matches_risc0_oracle() {
        let tsv = include_str!("../../test-vectors/ergo-stark/poseidon2_perm.tsv");
        let mut count = 0;
        for line in tsv
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            let (inp, outp) = line.split_once('\t').unwrap();
            let input = parse_u32s(inp);
            let expected = parse_u32s(outp);
            assert_eq!(input.len(), CELLS);
            assert_eq!(expected.len(), CELLS);
            let mut cells = [0u32; CELLS];
            cells.copy_from_slice(&input);
            Poseidon2::mix(&mut cells);
            assert_eq!(cells.to_vec(), expected, "perm mismatch on input {inp}");
            count += 1;
        }
        assert!(
            count >= 5,
            "expected several permutation vectors, got {count}"
        );
    }

    #[test]
    fn unpadded_hash_matches_risc0_oracle() {
        let tsv = include_str!("../../test-vectors/ergo-stark/poseidon2_hash.tsv");
        let mut count = 0;
        for line in tsv.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            // input may be empty (line begins with a tab).
            let (inp, outp) = line.split_once('\t').unwrap();
            let input = parse_u32s(inp);
            let expected = parse_u32s(outp);
            assert_eq!(expected.len(), 8);
            assert_eq!(
                Poseidon2::unpadded_hash(&input).to_vec(),
                expected,
                "hash mismatch on input {inp:?}"
            );
            count += 1;
        }
        assert!(count >= 5, "expected several hash vectors, got {count}");
    }
}
