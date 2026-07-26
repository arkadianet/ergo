//! The verifier-side Fiat-Shamir transcript over a RISC0 proof word stream —
//! a port of risc0-zkp `verify::read_iop::ReadIOP` specialized to the stock
//! succinct profile (BabyBear + Poseidon2 rng), together with its
//! [`Poseidon2Rng`] challenge generator.
//!
//! Version note (from the reference): risc0-zkp 1.2.6 and 3.0.4 are
//! value-identical here — same stream layout, same conversions, same rng; 3.0.4
//! only turns 1.2.6's panics on malformed input into a rejection. This port
//! follows the 3.0.4 rejection semantics: malformed input yields [`None`],
//! never a panic.
//!
//! The proof is a flat stream of `u32` words. Reads consume from the front;
//! [`ReadIop::commit`] mixes a digest into the transcript rng; the `random*`
//! methods draw Fiat-Shamir challenges. Reads never touch the rng and the rng
//! never consumes proof words — exactly upstream's split.
//!
//! Wire-form conversions (the Montgomery raw/canonical boundary):
//!  - [`ReadIop::read_u32s`] returns wire words untouched (no validation).
//!  - [`ReadIop::read_field_elem_slice`] returns CANONICAL values: each wire
//!    word is a Montgomery residue that must be `< P`, then mapped through
//!    [`BabyBear::from_raw`]. A word `>= P` rejects the read (returns `None`).
//!  - [`ReadIop::read_pod_slice`] returns RAW digest words with no validation.

use crate::baby_bear::BabyBear;
use crate::ext4::Ext4;
use crate::poseidon2::Poseidon2;
use crate::poseidon2_constants::CELLS;

/// The Fiat-Shamir transcript RNG of the stock RISC0 succinct profile — mirror
/// of risc0-zkp 1.2.6 `Poseidon2Rng`. A width-24 Poseidon2 sponge in duplex
/// mode.
#[derive(Clone)]
pub struct Poseidon2Rng {
    cells: [u32; CELLS],
    pool_used: usize,
}

impl Default for Poseidon2Rng {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2Rng {
    /// A fresh rng with a zeroed sponge state.
    pub fn new() -> Self {
        Poseidon2Rng {
            cells: [0u32; CELLS],
            pool_used: 0,
        }
    }

    /// Absorb a RISC0 digest. `digest_words` are RAW digest words as they appear
    /// on the wire — risc0 stores Montgomery residues in digests and adds them
    /// with `Elem::new_raw`, so each word is converted to its canonical value
    /// ([`BabyBear::from_raw`]) before entering this canonical-form state.
    ///
    /// If currently squeezing (`pool_used != 0`), permute first, then add the 8
    /// digest words into cells `0..8` and permute.
    pub fn mix(&mut self, digest_words: &[u32; 8]) {
        if self.pool_used != 0 {
            Poseidon2::mix(&mut self.cells);
            self.pool_used = 0;
        }
        let mut i = 0;
        while i < Poseidon2::CELLS_OUT {
            self.cells[i] = BabyBear::add(self.cells[i], BabyBear::from_raw(digest_words[i]));
            i += 1;
        }
        Poseidon2::mix(&mut self.cells);
    }

    /// Draw the next challenge element; refill (permute) after
    /// [`Poseidon2::CELLS_RATE`] draws.
    pub fn random_elem(&mut self) -> u32 {
        if self.pool_used == Poseidon2::CELLS_RATE {
            Poseidon2::mix(&mut self.cells);
            self.pool_used = 0;
        }
        let out = self.cells[self.pool_used];
        self.pool_used += 1;
        out
    }

    /// Draw FOUR elements, keep the first non-zero (in draw order), mask to
    /// `bits` low bits — upstream's exact (quirky) zero-avoidance; all four
    /// draws consume pool slots regardless.
    pub fn random_bits(&mut self, bits: u32) -> u32 {
        let mut v = self.random_elem();
        let mut i = 0;
        while i < 3 {
            let nv = self.random_elem();
            if v == 0 {
                v = nv;
            }
            i += 1;
        }
        (((1u64 << bits) - 1) & (v as u64)) as u32
    }

    /// Four sequential draws as `Ext4` coefficients.
    pub fn random_ext_elem(&mut self) -> Ext4 {
        Ext4::new(
            self.random_elem(),
            self.random_elem(),
            self.random_elem(),
            self.random_elem(),
        )
    }
}

/// Verifier-side transcript reader over a flat `u32` proof word stream.
pub struct ReadIop {
    proof: Vec<u32>,
    rng: Poseidon2Rng,
    pos: usize,
}

impl ReadIop {
    /// Wraps a proof word stream.
    pub fn new(proof: Vec<u32>) -> Self {
        ReadIop {
            proof,
            rng: Poseidon2Rng::new(),
            pos: 0,
        }
    }

    /// Words not yet consumed.
    pub fn remaining(&self) -> usize {
        self.proof.len() - self.pos
    }

    /// Read `n` raw `u32` words with no validation (upstream `read_u32s`).
    pub fn read_u32s(&mut self, n: usize) -> Option<Vec<u32>> {
        if n > self.remaining() {
            return None;
        }
        let out = self.proof[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Some(out)
    }

    /// Read `n` BabyBear elements, returned as CANONICAL values. Each wire word
    /// is a Montgomery residue and must be `< P` — upstream's checked cast; a
    /// word `>= P` rejects the read (returns `None`).
    ///
    /// Consumption semantics mirror the reference: a complete but unreduced
    /// slice still advances the proof cursor before it is rejected.
    pub fn read_field_elem_slice(&mut self, n: usize) -> Option<Vec<u32>> {
        if n > self.remaining() {
            return None;
        }
        let start = self.pos;
        self.pos += n;
        let mut out = Vec::with_capacity(n);
        let mut i = 0;
        while i < n {
            let w = self.proof[start + i];
            if w >= BabyBear::P {
                return None;
            }
            out.push(BabyBear::from_raw(w));
            i += 1;
        }
        Some(out)
    }

    /// Read `n` digests (8 RAW words each) with no validation — upstream
    /// `read_pod_slice::<Digest>(n)`, the only pod type the verifier reads.
    pub fn read_pod_slice(&mut self, n: usize) -> Option<Vec<[u32; 8]>> {
        if n > self.remaining() / Poseidon2::CELLS_OUT {
            return None;
        }
        let mut out = Vec::with_capacity(n);
        let mut i = 0;
        while i < n {
            let mut d = [0u32; 8];
            let off = self.pos + i * Poseidon2::CELLS_OUT;
            d.copy_from_slice(&self.proof[off..off + Poseidon2::CELLS_OUT]);
            out.push(d);
            i += 1;
        }
        self.pos += n * Poseidon2::CELLS_OUT;
        Some(out)
    }

    /// Read one RAW digest without the outer allocation of
    /// [`read_pod_slice`](Self::read_pod_slice). Only Merkle path verification
    /// (Layer 2) needs this allocation-minimal specialization; it mirrors the
    /// reference's `private[stark]` `readDigestRaw`.
    pub fn read_digest_raw(&mut self) -> Option<[u32; 8]> {
        if self.remaining() < Poseidon2::CELLS_OUT {
            return None;
        }
        let mut d = [0u32; 8];
        d.copy_from_slice(&self.proof[self.pos..self.pos + Poseidon2::CELLS_OUT]);
        self.pos += Poseidon2::CELLS_OUT;
        Some(d)
    }

    /// Mix a digest (RAW words, as on the wire) into the transcript rng. Words
    /// must be reduced (`< P`): every digest this verifier commits is either a
    /// Poseidon2 output (reduced by construction) or a wire digest already
    /// validated by the Merkle verifier.
    pub fn commit(&mut self, digest_raw: &[u32; 8]) {
        self.rng.mix(digest_raw);
    }

    /// True iff the entire proof stream has been consumed (upstream
    /// `verify_complete`).
    pub fn verify_complete(&self) -> bool {
        self.pos == self.proof.len()
    }

    /// Fiat-Shamir challenge draw — a canonical field element.
    pub fn random_elem(&mut self) -> u32 {
        self.rng.random_elem()
    }

    /// Cryptographically uniform `bits`-bit value (upstream `random_bits`).
    pub fn random_bits(&mut self, bits: u32) -> u32 {
        self.rng.random_bits(bits)
    }

    /// Uniform extension-field challenge (upstream `random_ext_elem`).
    pub fn random_ext_elem(&mut self) -> Ext4 {
        self.rng.random_ext_elem()
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

    fn to_arr8(v: &[u32]) -> [u32; 8] {
        let mut a = [0u32; 8];
        a.copy_from_slice(v);
        a
    }

    // ----- oracle parity -----

    #[test]
    fn poseidon2_rng_matches_risc0_oracle() {
        let tsv = include_str!("../../test-vectors/ergo-stark/poseidon2_rng.tsv");
        let mut rng = Poseidon2Rng::new();
        let mut ops = 0;
        for line in tsv
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            if let Some(rest) = line.strip_prefix("mix:") {
                let words = to_arr8(&parse_u32s(rest));
                rng.mix(&words);
            } else if let Some(rest) = line.strip_prefix("elem -> ") {
                assert_eq!(rng.random_elem(), rest.parse::<u32>().unwrap());
            } else if let Some(rest) = line.strip_prefix("bits:") {
                let (bits, val) = rest.split_once(" -> ").unwrap();
                assert_eq!(
                    rng.random_bits(bits.parse().unwrap()),
                    val.parse::<u32>().unwrap()
                );
            } else if let Some(rest) = line.strip_prefix("ext -> ") {
                let e = parse_u32s(rest);
                assert_eq!(rng.random_ext_elem(), Ext4::new(e[0], e[1], e[2], e[3]));
            } else {
                panic!("unrecognized rng op: {line}");
            }
            ops += 1;
        }
        assert!(ops >= 40, "expected the full rng script, got {ops}");
    }

    #[test]
    fn readiop_transcript_matches_risc0_oracle() {
        let tsv = include_str!("../../test-vectors/ergo-stark/readiop_script.tsv");
        let mut iop: Option<ReadIop> = None;
        let mut ops = 0;
        for line in tsv
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            if let Some(rest) = line.strip_prefix("proof:") {
                iop = Some(ReadIop::new(parse_u32s(rest)));
            } else if let Some(rest) = line.strip_prefix("u32s:") {
                let (n, expect) = rest.split_once(" -> ").unwrap();
                let got = iop.as_mut().unwrap().read_u32s(n.parse().unwrap()).unwrap();
                assert_eq!(got, parse_u32s(expect), "u32s");
            } else if let Some(rest) = line.strip_prefix("elems:") {
                let (n, expect) = rest.split_once(" -> ").unwrap();
                let got = iop
                    .as_mut()
                    .unwrap()
                    .read_field_elem_slice(n.parse().unwrap())
                    .unwrap();
                assert_eq!(got, parse_u32s(expect), "elems");
            } else if let Some(rest) = line.strip_prefix("pod:") {
                let (n, expect) = rest.split_once(" -> ").unwrap();
                let got = iop
                    .as_mut()
                    .unwrap()
                    .read_pod_slice(n.parse().unwrap())
                    .unwrap();
                let flat: Vec<u32> = got.iter().flatten().copied().collect();
                assert_eq!(flat, parse_u32s(expect), "pod");
            } else if let Some(rest) = line.strip_prefix("commit:") {
                let d = to_arr8(&parse_u32s(rest));
                iop.as_mut().unwrap().commit(&d);
            } else if let Some(rest) = line.strip_prefix("elem -> ") {
                assert_eq!(
                    iop.as_mut().unwrap().random_elem(),
                    rest.parse::<u32>().unwrap()
                );
            } else if let Some(rest) = line.strip_prefix("bits:") {
                let (bits, val) = rest.split_once(" -> ").unwrap();
                assert_eq!(
                    iop.as_mut().unwrap().random_bits(bits.parse().unwrap()),
                    val.parse::<u32>().unwrap()
                );
            } else if let Some(rest) = line.strip_prefix("ext -> ") {
                let e = parse_u32s(rest);
                assert_eq!(
                    iop.as_mut().unwrap().random_ext_elem(),
                    Ext4::new(e[0], e[1], e[2], e[3])
                );
            } else if line == "complete" {
                assert!(iop.as_ref().unwrap().verify_complete(), "verify_complete");
            } else {
                panic!("unrecognized readiop op: {line}");
            }
            ops += 1;
        }
        assert!(ops >= 15, "expected the full readiop script, got {ops}");
    }

    // ----- error paths -----

    #[test]
    fn field_elem_slice_rejects_word_ge_p_but_advances_cursor() {
        // Matches StarkPrimitiveAllocationSpec: an unreduced word rejects, yet
        // the cursor advances past the consumed slice.
        let canonical = [0u32, 1, BabyBear::P - 1];
        let raw: Vec<u32> = canonical.iter().map(|&x| BabyBear::to_raw(x)).collect();
        let mut proof = raw.clone();
        proof.push(BabyBear::P); // >= P: rejects
        proof.push(7);
        let mut iop = ReadIop::new(proof);

        assert_eq!(iop.read_field_elem_slice(3).unwrap(), canonical.to_vec());
        assert_eq!(iop.read_field_elem_slice(1), None);
        assert_eq!(iop.remaining(), 1);
        assert_eq!(iop.read_u32s(1).unwrap(), vec![7]);
        assert!(iop.verify_complete());
    }

    #[test]
    fn read_digest_raw_specialization() {
        let proof: Vec<u32> = (0..8).map(|i| i * 13 + 5).collect();
        let mut iop = ReadIop::new(proof.clone());
        let d = iop.read_digest_raw().unwrap();
        assert_eq!(d.to_vec(), proof);
        assert!(iop.verify_complete());
        assert_eq!(iop.read_digest_raw(), None);
    }

    #[test]
    fn short_reads_return_none() {
        let mut iop = ReadIop::new(vec![1, 2, 3]);
        assert_eq!(iop.read_u32s(4), None);
        assert_eq!(iop.read_pod_slice(1), None);
        assert_eq!(iop.remaining(), 3);
    }
}
