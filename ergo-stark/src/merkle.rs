//! The IOP Merkle branch verifier of the EIP-0045 `verifyStark` raw-seal STARK
//! verifier — a faithful port of the reference sigmastate `MerkleVerifier`
//! (mirror of risc0-zkp `verify::merkle::MerkleTreeVerifier` with the
//! Poseidon2 hash suite). Consensus-critical: it must accept exactly the
//! branches the reference accepts and reject exactly the ones it rejects.
//!
//! # Tree shape (upstream `MerkleTreeParams`)
//! `row_size` leaves (a power of two), each hashing `col_size` field elements;
//! `top_size = 2^t` where `t` is the largest layer index (`< layers`) with
//! `2^t <= queries` — the layer above which hashes are checked only once.
//! Virtual node `i` has children `2i` / `2i+1`; the root is node 1; the top
//! row occupies nodes `[top_size, 2·top_size)` and is read from the proof
//! stream, while nodes `[1, top_size)` are recomputed from it at construction.
//!
//! # Transcript protocol (the Fiat-Shamir coupling, ported exactly)
//! [`MerkleVerifier::create`] reads the `top_size` top-row digests from the
//! IOP, folds them up to the root, and commits ONLY the root to the transcript
//! rng. [`MerkleVerifier::verify`] reads the row and path digests without
//! touching the rng.
//!
//! # Wire-form decisions (each traced to the upstream flow)
//! - Digests are held and compared in RAW (Montgomery) word form — upstream
//!   compares `Digest` words directly and never decodes them.
//! - Node hashing converts at the hash boundary: upstream `hash_pair`
//!   reinterprets raw digest words as field elements (`Elem::new_raw`) and
//!   sponges them, so [`hash_pair_raw`] maps raw -> canonical
//!   ([`BabyBear::from_raw`]) for [`Poseidon2::hash_pair`] and re-encodes the
//!   output with [`BabyBear::to_raw`] (upstream `to_digest` stores
//!   `as_u32_montgomery`).
//! - Leaf hashing consumes the row via [`ReadIop::read_field_elem_slice`]
//!   (canonical values — upstream `hash_elem_slice` sponges the elements
//!   themselves), then re-encodes the digest to raw form.
//! - Wire digest words are validated `< P` exactly where risc0-zkp 3.0.4 checks
//!   `is_digest_valid` and returns `ReceiptFormatError`: the top row (validated
//!   before folding) and every path digest in [`MerkleVerifier::verify`]. For
//!   the `top_size == 1` corner upstream commits the raw top word unchecked; an
//!   unreduced word there can never equal a recomputed digest word (hash
//!   outputs are reduced), so every such proof is rejected by upstream too —
//!   rejecting at construction preserves accept/reject parity while keeping the
//!   canonical-form rng state sound.
//!
//! Rejection style mirrors the reference: `Result<_, String>`, never a panic on
//! malformed proof bytes; `assert!` guards only verifier-chosen parameters.

use crate::baby_bear::BabyBear;
use crate::poseidon2::Poseidon2;
use crate::poseidon2_constants::CELLS;
use crate::read_iop::ReadIop;

/// Digest length in field elements (`Poseidon2::CELLS_OUT`), fixed at 8.
const DIGEST_WORDS: usize = Poseidon2::CELLS_OUT;

/// An IOP Merkle commitment verifier over one committed column-major matrix.
///
/// Construct with [`MerkleVerifier::create`] (which reads the top row and
/// commits the root to the transcript), then open branches with
/// [`MerkleVerifier::verify`].
pub struct MerkleVerifier {
    row_size: usize,
    col_size: usize,
    top_size: usize,
    /// The `top_size` top-row digests, RAW words, read from the proof stream.
    top: Vec<[u32; DIGEST_WORDS]>,
    /// Nodes `[1, top_size)` folded from the top row; `rest[i - 1]` is node `i`.
    /// Empty when `top_size == 1` (the root is then `top[0]`).
    rest: Vec<[u32; DIGEST_WORDS]>,
}

impl MerkleVerifier {
    /// Number of committed rows (leaves).
    pub fn row_size(&self) -> usize {
        self.row_size
    }

    /// Number of field elements hashed per leaf.
    pub fn col_size(&self) -> usize {
        self.col_size
    }

    /// The root digest (virtual node 1) in RAW word form. Returned by value, so
    /// the caller can never mutate the verifier's internal state through it.
    pub fn root_raw(&self) -> [u32; DIGEST_WORDS] {
        if self.top_size == 1 {
            self.top[0]
        } else {
            self.rest[0]
        }
    }

    /// Construct by reading the top row from `iop` and committing the root —
    /// upstream `MerkleTreeVerifier::new`.
    ///
    /// `row_size` must be a power of two and `col_size`/`queries` positive
    /// (verifier parameters, not proof data); a malformed proof stream yields
    /// `Err`.
    ///
    /// # Panics
    /// Panics (via `assert!`) if a verifier-chosen parameter is invalid,
    /// mirroring the reference `require`.
    pub fn create(
        iop: &mut ReadIop,
        row_size: usize,
        col_size: usize,
        queries: usize,
    ) -> Result<MerkleVerifier, String> {
        assert!(
            row_size > 0 && (row_size & (row_size - 1)) == 0,
            "rowSize not a power of 2: {row_size}"
        );
        assert!(col_size > 0, "colSize must be positive: {col_size}");
        assert!(queries > 0, "queries must be positive: {queries}");

        // Upstream MerkleTreeParams::new: the top layer is the deepest layer
        // (strictly below the leaves) of size at most `queries`.
        let layers = 31 - (row_size as u32).leading_zeros();
        let mut top_layer = 0u32;
        let mut i = 1u32;
        while i < layers && (1u32 << i) <= queries as u32 {
            top_layer = i;
            i += 1;
        }
        let top_size = 1usize << top_layer;

        let top = match iop.read_pod_slice(top_size) {
            None => return Err("merkle top row: truncated proof".to_string()),
            Some(t) => t,
        };
        if !top.iter().all(all_reduced) {
            return Err("merkle top row: unreduced digest word".to_string());
        }

        // Fold the top row up to the root: children of virtual node i are at
        // 2i / 2i+1; rest[i - 1] holds node i for i in [1, top_size).
        let mut rest = vec![[0u32; DIGEST_WORDS]; top_size - 1];
        let mut n = top_size as isize - 1;
        while n >= (top_size / 2) as isize && n >= 1 {
            let nn = n as usize;
            rest[nn - 1] = hash_pair_raw(&top[2 * nn - top_size], &top[2 * nn + 1 - top_size]);
            n -= 1;
        }
        while n >= 1 {
            let nn = n as usize;
            rest[nn - 1] = hash_pair_raw(&rest[2 * nn - 1], &rest[2 * nn]);
            n -= 1;
        }

        let verifier = MerkleVerifier {
            row_size,
            col_size,
            top_size,
            top,
            rest,
        };
        let root = verifier.root_raw();
        iop.commit(&root);
        Ok(verifier)
    }

    /// Verify one branch read from `iop` against row `idx`; returns the
    /// CANONICAL row values on success. Mirror of upstream `verify`: rejects an
    /// out-of-range index, reads `col_size` elements (the leaf), then one
    /// "other" digest per level below the top row, ascending with left/right
    /// order decided by the index's low bit.
    ///
    /// The reference also rejects a negative index; that guard is vacuous for
    /// the unsigned index domain here, so only the `>= row_size` bound remains.
    pub fn verify(&self, iop: &mut ReadIop, idx: usize) -> Result<Vec<u32>, String> {
        if idx >= self.row_size {
            return Err(format!(
                "merkle query out of range: idx {idx}, rows {}",
                self.row_size
            ));
        }
        let row = match iop.read_field_elem_slice(self.col_size) {
            None => return Err("merkle branch: bad row data (truncated or word >= P)".to_string()),
            Some(r) => r,
        };
        let mut cur = Poseidon2::unpadded_hash(&row).map(BabyBear::to_raw);
        let mut i = idx + self.row_size;
        while i >= 2 * self.top_size {
            let other = match iop.read_digest_raw() {
                None => return Err("merkle branch: truncated path digest".to_string()),
                Some(o) => o,
            };
            if !all_reduced(&other) {
                return Err("merkle branch: unreduced path digest word".to_string());
            }
            let low_bit = i & 1;
            i /= 2;
            cur = if low_bit == 1 {
                hash_pair_raw(&other, &cur)
            } else {
                hash_pair_raw(&cur, &other)
            };
        }
        let present = if i >= self.top_size {
            &self.top[i - self.top_size]
        } else {
            &self.rest[i - 1]
        };
        if present == &cur {
            Ok(row)
        } else {
            Err("merkle branch: root path mismatch".to_string())
        }
    }
}

/// True iff every word of a digest is a reduced residue (`< P` unsigned).
fn all_reduced(digest_raw: &[u32; DIGEST_WORDS]) -> bool {
    digest_raw.iter().all(|&w| w < BabyBear::P)
}

/// Node compression over RAW digests — upstream `hash_pair` reinterprets raw
/// words as field elements and sponges them; the output is re-encoded to raw.
fn hash_pair_raw(a_raw: &[u32; DIGEST_WORDS], b_raw: &[u32; DIGEST_WORDS]) -> [u32; DIGEST_WORDS] {
    let a = a_raw.map(BabyBear::from_raw);
    let b = b_raw.map(BabyBear::from_raw);
    Poseidon2::hash_pair(&a, &b).map(BabyBear::to_raw)
}

// A compile-time cross-check that the local digest width matches the crate's
// Poseidon2 sponge output; keeps `[u32; DIGEST_WORDS]` and `[u32; 8]`
// interchangeable across the module boundary.
const _: () = assert!(DIGEST_WORDS == 8);
const _: () = assert!(CELLS >= 2 * DIGEST_WORDS);

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn words(s: &str) -> Vec<u32> {
        if s.is_empty() {
            Vec::new()
        } else {
            // Parse via u64 so values >= 2^31 round-trip into bit-identical u32.
            s.split(',')
                .map(|w| w.trim().parse::<u64>().unwrap() as u32)
                .collect()
        }
    }

    fn to_digest(v: &[u32]) -> [u32; 8] {
        let mut d = [0u32; 8];
        d.copy_from_slice(v);
        d
    }

    /// Smallest `r` with `2^r >= v` — the query index draw uses
    /// `random_bits(log2_ceil(rows))`.
    fn log2_ceil(v: usize) -> usize {
        let mut r = 0;
        while (1usize << r) < v {
            r += 1;
        }
        r
    }

    struct TreeVec {
        rows: usize,
        cols: usize,
        queries: usize,
        proof: Vec<u32>,
        root: [u32; 8],
        query_rows: Vec<(usize, Vec<u32>)>,
        bad_words: Vec<(usize, u32)>,
        truncates: Vec<usize>,
        bad_queries: Vec<usize>,
    }

    fn parse_trees() -> Vec<TreeVec> {
        let tsv = include_str!("../../test-vectors/ergo-stark/merkle_kat.tsv");
        let mut trees = Vec::new();
        let mut cur: Option<TreeVec> = None;
        for line in tsv
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            if let Some(rest) = line.strip_prefix("tree:") {
                let p: Vec<usize> = rest.split(',').map(|x| x.parse().unwrap()).collect();
                cur = Some(TreeVec {
                    rows: p[0],
                    cols: p[1],
                    queries: p[2],
                    proof: Vec::new(),
                    root: [0u32; 8],
                    query_rows: Vec::new(),
                    bad_words: Vec::new(),
                    truncates: Vec::new(),
                    bad_queries: Vec::new(),
                });
            } else if let Some(rest) = line.strip_prefix("proof:") {
                cur.as_mut().unwrap().proof = words(rest);
            } else if let Some(rest) = line.strip_prefix("root:") {
                cur.as_mut().unwrap().root = to_digest(&words(rest));
            } else if let Some(rest) = line.strip_prefix("query:") {
                let (idx, row) = rest.split_once(" -> ").unwrap();
                cur.as_mut()
                    .unwrap()
                    .query_rows
                    .push((idx.trim().parse().unwrap(), words(row)));
            } else if let Some(rest) = line.strip_prefix("badword:") {
                let (pos, xor) = rest.split_once(',').unwrap();
                cur.as_mut()
                    .unwrap()
                    .bad_words
                    .push((pos.parse().unwrap(), xor.parse::<u64>().unwrap() as u32));
            } else if let Some(rest) = line.strip_prefix("truncate:") {
                cur.as_mut().unwrap().truncates.push(rest.parse().unwrap());
            } else if let Some(rest) = line.strip_prefix("badquery:") {
                cur.as_mut()
                    .unwrap()
                    .bad_queries
                    .push(rest.parse().unwrap());
            } else if line == "endtree" {
                trees.push(cur.take().unwrap());
            } else if line != "complete" {
                panic!("unknown merkle KAT line: {line}");
            }
        }
        trees
    }

    /// Full replay of a tree vector against its recorded expectations — mirror
    /// of the generator's `oracle_replay_ok`. `wrong_query`: verify that query
    /// with `(idx + 1) % rows`, "passing" only if the wrong row is (impossibly)
    /// accepted.
    fn replay_ok(v: &TreeVec, proof: &[u32], wrong_query: Option<usize>) -> bool {
        let mut iop = ReadIop::new(proof.to_vec());
        let ver = match MerkleVerifier::create(&mut iop, v.rows, v.cols, v.queries) {
            Err(_) => return false,
            Ok(x) => x,
        };
        if ver.root_raw() != v.root {
            return false;
        }
        let mut ok = true;
        let mut accepted_wrong_row = false;
        for (q, (exp_idx, exp_row)) in v.query_rows.iter().enumerate() {
            if !ok || accepted_wrong_row {
                break;
            }
            let mut idx = iop.random_bits(log2_ceil(v.rows) as u32) as usize;
            if idx != *exp_idx {
                ok = false;
            } else {
                if wrong_query == Some(q) {
                    idx = (idx + 1) % v.rows;
                }
                match ver.verify(&mut iop, idx) {
                    Ok(row) => {
                        if wrong_query == Some(q) {
                            accepted_wrong_row = true;
                        } else if &row != exp_row {
                            ok = false;
                        }
                    }
                    Err(_) => ok = false,
                }
            }
        }
        ok && (accepted_wrong_row || iop.verify_complete())
    }

    // ----- oracle parity -----

    #[test]
    fn replays_prover_built_trees_root_indices_rows_completion() {
        let trees = parse_trees();
        assert!(!trees.is_empty());
        for v in &trees {
            let mut iop = ReadIop::new(v.proof.clone());
            let ver = MerkleVerifier::create(&mut iop, v.rows, v.cols, v.queries).unwrap();
            assert_eq!(ver.root_raw(), v.root, "tree {}x{} root", v.rows, v.cols);
            // root_raw hands out a copy: mutating it cannot corrupt the root.
            let mut exposed = ver.root_raw();
            exposed[0] ^= 1;
            assert_eq!(ver.root_raw(), v.root, "root_raw is a defensive copy");
            for (exp_idx, exp_row) in &v.query_rows {
                let idx = iop.random_bits(log2_ceil(v.rows) as u32) as usize;
                assert_eq!(idx, *exp_idx, "query index draw");
                assert_eq!(ver.verify(&mut iop, idx).unwrap(), *exp_row, "query row");
            }
            assert!(iop.verify_complete(), "verify_complete");
        }
    }

    // ----- error paths -----

    #[test]
    fn rejects_corrupted_proof_words() {
        let trees = parse_trees();
        assert!(trees.iter().any(|v| !v.bad_words.is_empty()));
        for v in &trees {
            for &(pos, xor) in &v.bad_words {
                let mut corrupted = v.proof.clone();
                corrupted[pos] ^= xor;
                assert!(
                    !replay_ok(v, &corrupted, None),
                    "tree {}x{} badword {pos}^{xor} must reject",
                    v.rows,
                    v.cols
                );
            }
        }
    }

    #[test]
    fn rejects_truncated_proofs() {
        let trees = parse_trees();
        for v in &trees {
            for &keep in &v.truncates {
                assert!(
                    !replay_ok(v, &v.proof[..keep], None),
                    "tree {}x{} truncate {keep} must reject",
                    v.rows,
                    v.cols
                );
            }
        }
    }

    #[test]
    fn rejects_wrong_row_index() {
        let trees = parse_trees();
        assert!(trees.iter().any(|v| !v.bad_queries.is_empty()));
        for v in &trees {
            for &q in &v.bad_queries {
                assert!(
                    !replay_ok(v, &v.proof, Some(q)),
                    "tree {}x{} badquery {q} must reject",
                    v.rows,
                    v.cols
                );
            }
        }
    }

    #[test]
    fn rejects_out_of_range_index_without_reading_stream() {
        let trees = parse_trees();
        let v = &trees[0];
        let mut iop = ReadIop::new(v.proof.clone());
        let ver = MerkleVerifier::create(&mut iop, v.rows, v.cols, v.queries).unwrap();
        let before = iop.remaining();
        assert!(ver.verify(&mut iop, v.rows).is_err());
        assert_eq!(iop.remaining(), before, "out-of-range verify reads nothing");
    }
}
