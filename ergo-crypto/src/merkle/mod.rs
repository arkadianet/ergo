use crate::autolykos::common::blake2b256;

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_NODE_PREFIX: u8 = 0x01;

/// Compute hash of a Merkle leaf: Blake2b256(0x00 ++ data).
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + data.len());
    input.push(LEAF_PREFIX);
    input.extend_from_slice(data);
    blake2b256(&input)
}

/// Public leaf-digest rule for a transaction id in a block's
/// `transactions_root` tree: `Blake2b256(0x00 ‖ tx_id)`.
///
/// Exposed so external inclusion verifiers (the peg-in verifier binds
/// an attacker-supplied batch-proof leaf to a *recomputed* tx id —
/// g25-pegmint-packaging §5.2.5) share the exact scorex leaf rule
/// instead of re-deriving the prefix byte.
pub fn tx_leaf_digest(tx_id: &[u8; 32]) -> [u8; 32] {
    leaf_hash(tx_id)
}

/// Compute hash of a Merkle internal node: Blake2b256(0x01 ++ left ++ right).
///
/// Even-pair reducer. The fixed `[u8; 32]` signature is the
/// load-bearing contract — `calc_top_node` uses it to guarantee at the
/// type level that both children are full 32-byte hashes (never the
/// odd-trailing empty-sibling case, which goes through
/// [`internal_hash_dyn`]). Body delegates to the variable-length
/// helper for a single source of truth on the preimage layout.
fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    internal_hash_dyn(left, right)
}

/// Compute the Merkle tree root hash from a list of leaf data.
///
/// Matches scorex `MerkleTree.apply` + `calcTopNode`:
/// - Each leaf is hashed as Blake2b256(0x00 ++ leaf_data)
/// - Nodes are paired bottom-up; odd nodes pair with EmptyNode (hash = [])
/// - Internal nodes: Blake2b256(0x01 ++ left.hash ++ right.hash)
///
/// Empty input returns `Blake2b256([])` — the leaf-prefix rule is
/// bypassed in this special case, matching Scala's
/// `Algos.emptyMerkleTreeRoot = hash(LeafData @@ Array[Byte]())`.
pub fn merkle_tree_root(elements: &[&[u8]]) -> [u8; 32] {
    if elements.is_empty() {
        // Ergo's Algos.emptyMerkleTreeRoot = hash(LeafData @@ Array[Byte]())
        // = hash of empty byte array (NOT leaf_hash of empty)
        return blake2b256(&[]);
    }
    // Last level holds exactly the root (build_levels guarantees that for
    // non-empty input).
    let levels = build_levels(elements);
    levels[levels.len() - 1][0]
}

/// Build every level of the Merkle reduction bottom-up. Level 0 is the
/// hashed leaves; the last level is a single-element vector holding the
/// root. Stores only the real 32-byte hashes at each level — odd
/// trailing nodes do **not** materialize a phantom empty sibling, that
/// is reconstructed at proof-extraction time from an out-of-range
/// sibling lookup.
///
/// Shared by [`merkle_tree_root`] and [`merkle_proof_by_index`] so the
/// canonical root and any per-index proof are produced from the exact
/// same reduction. Mirrors scorex `calcTopNode`
/// (`scorex/crypto/authds/merkle/MerkleTree.scala:22-40`):
/// - even pairs → [`internal_hash`] (`0x01 ++ left ++ right`)
/// - odd trailing → [`internal_hash_dyn(left, &[])`] (`0x01 ++ left.hash`,
///   matching `EmptyNode = []`)
///
/// Caller must ensure `elements` is non-empty (the empty case is
/// handled separately via the canonical `Algos.emptyMerkleTreeRoot`).
fn build_levels(elements: &[&[u8]]) -> Vec<Vec<[u8; 32]>> {
    debug_assert!(
        !elements.is_empty(),
        "build_levels invariant: caller filters empty inputs"
    );
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    levels.push(elements.iter().map(|e| leaf_hash(e)).collect());

    // Always reduce at least once: even a single-leaf input must be
    // wrapped via the odd-trailing rule into `InternalNode(Leaf,
    // EmptyNode)` (scrypto `MerkleTree.scala:156-165`,
    // `Node.scala:51-53`). The post-reduction length check terminates
    // the loop the moment we've collapsed to a single root node.
    loop {
        let current = levels.last().unwrap();
        let next: Vec<[u8; 32]> = current
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    internal_hash(&chunk[0], &chunk[1])
                } else {
                    internal_hash_dyn(&chunk[0], &[])
                }
            })
            .collect();
        levels.push(next);
        if levels.last().unwrap().len() <= 1 {
            break;
        }
    }
    levels
}

/// Compute the Ergo transactionsRoot for a block.
///
/// - Version 1: Merkle root of transaction IDs only
/// - Version 2+: Merkle root of (transaction IDs ++ witness IDs)
///
/// Transaction ID = serialized ID (32 bytes, already a Blake2b256 hash).
/// Witness ID = Blake2b256(concatenated spending proofs).drop(1) → 31 bytes.
pub fn transactions_root(tx_ids: &[&[u8]], witness_ids: Option<&[&[u8]]>) -> [u8; 32] {
    let mut leaves: Vec<&[u8]> = tx_ids.to_vec();
    if let Some(wids) = witness_ids {
        leaves.extend_from_slice(wids);
    }
    merkle_tree_root(&leaves)
}

/// Single-leaf inclusion proof.
///
/// Wire shape per scrypto `MerkleProof`
/// (`scorex/crypto/authds/merkle/MerkleProof.scala:25`):
/// - `leaf_data`: the original leaf bytes (NOT the leaf hash). The
///   verifier prefix-hashes them with `0x00` to recover the leaf hash.
/// - `levels`: bottom-up siblings paired with side bytes. `0` (Left)
///   means the *computed* hash sits on the left and the stored sibling
///   on the right; `1` (Right) is the opposite. Empty siblings (odd
///   nodes paired with `EmptyNode`) carry an empty `Vec` — JSON layer
///   serializes that as `""` per `ApiCodecs.scala:50`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProofRaw {
    /// Original leaf bytes (not the leaf hash). The verifier
    /// prefix-hashes them with `0x00` to recover the leaf hash.
    pub leaf_data: Vec<u8>,
    /// Bottom-up sibling list. Each entry is `(sibling_bytes, side)`
    /// where `side == 0` means the computed hash is on the left and
    /// `side == 1` means on the right; an empty `sibling_bytes`
    /// represents the `EmptyNode` pairing for odd-trailing leaves.
    pub levels: Vec<(Vec<u8>, u8)>,
}

/// Build a Merkle proof for the leaf at `index` against the tree
/// constructed from `elements`.
///
/// Returns `None` if `index` is out of range or `elements` is empty.
/// Mirrors scrypto `MerkleTree.proofByIndex`
/// (`scorex/crypto/authds/merkle/MerkleTree.scala:22-40`):
/// - depth = number of reduction steps (single-leaf trees produce
///   depth 1 with one empty-sibling level — the lone leaf is reduced
///   once via the odd-trailing rule against `EmptyNode`)
/// - each level emits the sibling that pairs with the current node
/// - sides: `0` (Left) = computed-hash on the left, sibling on the
///   right; `1` (Right) = the opposite
///
/// Walks the same reduction levels that [`merkle_tree_root`] consumes
/// (via `build_levels`) so the proof and root are guaranteed to be
/// produced from one tree, not two parallel reductions. Empty siblings
/// (the odd-trailing case) are synthesized from out-of-range sibling
/// lookups, never as phantom nodes in the level vectors.
pub fn merkle_proof_by_index(elements: &[&[u8]], index: usize) -> Option<MerkleProofRaw> {
    if elements.is_empty() || index >= elements.len() {
        return None;
    }

    let levels = build_levels(elements);

    // Walk every level except the root: at each step record the
    // sibling that pairs with the current node and which side our
    // node sits on, then halve the index for the next level up. For a
    // single leaf, `build_levels` returns `[[leaf_hash], [root]]`, so
    // this walk emits exactly one (empty-sibling, side=0) entry —
    // matching scrypto's `InternalNode(Leaf, EmptyNode)` wrapping at
    // `MerkleTree.scala:156-165`.
    let mut idx = index;
    let mut proof_levels: Vec<(Vec<u8>, u8)> = Vec::with_capacity(levels.len() - 1);
    for level in &levels[..levels.len() - 1] {
        let sibling_idx = idx ^ 1;
        let sibling = if sibling_idx < level.len() {
            level[sibling_idx].to_vec()
        } else {
            // Odd-trailing leaf at this level: paired with `EmptyNode`,
            // whose hash is `[]`. Synthesized here rather than stored
            // in `level`, so the level vectors only ever hold real
            // 32-byte digests.
            Vec::new()
        };
        // Side: if our position is even (left child), sibling is on
        // the right → `LeftSide = 0`. Mirrors `MerkleProof.scala:31-36`.
        let side: u8 = if idx.is_multiple_of(2) { 0 } else { 1 };
        proof_levels.push((sibling, side));
        idx /= 2;
    }

    Some(MerkleProofRaw {
        leaf_data: elements[index].to_vec(),
        levels: proof_levels,
    })
}

/// `internal_hash` variant accepting variable-length inputs so the
/// empty-sibling case (right-child = empty bytes) produces the same
/// 33-byte preimage as scrypto's odd-node reduction (`Node.scala:22`
/// with `EmptyNode.hash = []`).
fn internal_hash_dyn(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + left.len() + right.len());
    input.push(INTERNAL_NODE_PREFIX);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    blake2b256(&input)
}

/// Compact batch Merkle proof entry: a sibling digest (`None` =
/// empty-sibling odd-trailing case) paired with which side it joins
/// during reduction. Wire-side definition lives in
/// `ergo_ser::batch_merkle_proof` — this is the in-memory analog
/// produced by [`merkle_proof_by_indices`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchProofEntry {
    /// Sibling digest. `None` represents `EmptyByteArray` (no
    /// right child during reduction).
    pub digest: Option<[u8; 32]>,
    /// `0` = left side, `1` = right side. Same encoding as scrypto
    /// `Side`.
    pub side: u8,
}

/// Result of [`merkle_proof_by_indices`]: the sorted
/// `(leaf_index, leaf_hash)` pairs that were proven, plus the
/// bottom-up sibling-digest list (`None` digest entries are the
/// `EmptyByteArray` placeholders for the odd-trailing case).
///
/// Named distinct from `ergo_ser::batch_merkle_proof::BatchMerkleProof`
/// because that struct is the *serializable wire form* (with
/// `Side::{Left, Right}` tags); this alias is the *computed in-memory
/// form* before any wire tagging. Callers convert by mapping each
/// `BatchProofEntry.side` byte to a `Side` variant.
pub type IndexedBatchProof = (Vec<(u32, [u8; 32])>, Vec<BatchProofEntry>);

/// Compact multi-leaf Merkle proof for a subset of leaf indices
/// against a tree built from `elements`. Mirrors scrypto
/// `MerkleTree.proofByIndices` (`MerkleTree.scala:53-104`).
///
/// Returns `Some((sorted_indices_with_leaf_hashes, proofs))` when
/// every index is in range, else `None`. The output shape pairs
/// directly with `ergo_ser::batch_merkle_proof::BatchMerkleProof`
/// — callers convert into the wire struct by tagging each
/// `BatchProofEntry` with `Side::{Left, Right}`.
///
/// Algorithm (per scrypto, condensed):
/// 1. Sort + dedup the requested indices.
/// 2. Initial layer = leaf hashes of every element.
/// 3. At each level, pair indices with their immediate sibling
///    (`(i, i+1)` for even `i`, `(i-1, i)` for odd). Dedup the
///    pair list.
/// 4. For each side of each pair NOT already in our index set,
///    emit a proof entry — sibling digest + side byte. Empty siblings
///    (out-of-range in the current level) emit a `None` digest.
/// 5. Move to the next level: indices become `pair.0 / 2`; layer
///    becomes adjacent pairs hashed bottom-up.
/// 6. Repeat until the layer collapses to a single node (root).
pub fn merkle_proof_by_indices(elements: &[&[u8]], indices: &[u32]) -> Option<IndexedBatchProof> {
    if elements.is_empty() || indices.is_empty() {
        return None;
    }
    let n = elements.len() as u32;
    if !indices.iter().all(|i| *i < n) {
        return None;
    }

    // Sort + dedup.
    let mut sorted_indices: Vec<u32> = indices.to_vec();
    sorted_indices.sort_unstable();
    sorted_indices.dedup();

    let leaf_hashes: Vec<[u8; 32]> = elements.iter().map(|e| leaf_hash(e)).collect();
    let returned_indices: Vec<(u32, [u8; 32])> = sorted_indices
        .iter()
        .map(|&i| (i, leaf_hashes[i as usize]))
        .collect();

    let mut current_indices = sorted_indices.clone();
    let mut current_layer = leaf_hashes;
    let mut proofs: Vec<BatchProofEntry> = Vec::new();

    // Always reduce at least once: a single-leaf tree's root is
    // `Blake2b256(0x01 ++ leaf_hash)` (the odd-trailing wrap from
    // `MerkleTree.scala:156-165`), so even when current_layer starts
    // at size 1 we emit a (None, Right) proof entry and produce the
    // wrapped root in the next layer. The loop terminates the first
    // time the computed next_layer collapses to a single node.
    loop {
        // Pair each index with its sibling, dedup the pairs.
        let mut pairs: Vec<(u32, u32)> = current_indices
            .iter()
            .map(|&i| if i % 2 == 0 { (i, i + 1) } else { (i - 1, i) })
            .collect();
        pairs.dedup();

        // Emit proof entries for siblings NOT in our proven set.
        let in_set: std::collections::BTreeSet<u32> = current_indices.iter().copied().collect();
        for (lo, hi) in &pairs {
            for &i in &[*lo, *hi] {
                if !in_set.contains(&i) {
                    let side = if i % 2 == 0 { 0u8 } else { 1u8 };
                    let digest = current_layer.get(i as usize).copied();
                    proofs.push(BatchProofEntry { digest, side });
                }
            }
        }

        // Build the next layer.
        let mut next_layer: Vec<[u8; 32]> = Vec::with_capacity(current_layer.len().div_ceil(2));
        for chunk in current_layer.chunks(2) {
            if chunk.len() == 2 {
                next_layer.push(internal_hash(&chunk[0], &chunk[1]));
            } else {
                next_layer.push(internal_hash_dyn(&chunk[0], &[]));
            }
        }

        if next_layer.len() <= 1 {
            break;
        }
        current_indices = pairs.iter().map(|(lo, _)| lo / 2).collect();
        current_layer = next_layer;
    }

    Some((returned_indices, proofs))
}

/// Verify a `MerkleProofRaw` against an expected root. Mirrors
/// `MerkleProof.scala:28-37`. Used in tests and by consumers that
/// want a self-check before trusting the proof.
pub fn merkle_proof_verify(proof: &MerkleProofRaw, expected_root: &[u8; 32]) -> bool {
    let mut hash: Vec<u8> = leaf_hash(&proof.leaf_data).to_vec();
    for (sibling, side) in &proof.levels {
        let combined = if *side == 0 {
            internal_hash_dyn(&hash, sibling)
        } else {
            internal_hash_dyn(sibling, &hash)
        };
        hash = combined.to_vec();
    }
    hash.as_slice() == expected_root.as_slice()
}

/// Compute extension root hash from key-value fields.
///
/// Leaf encoding per Scala `Extension.kvToLeaf`:
///   `[key.len() as u8] ++ key_bytes ++ value_bytes`
///
/// Same Merkle tree as transactions (leaf prefix 0x00, internal 0x01,
/// EmptyNode pairing for odd counts). Empty fields → `Blake2b256([])`.
pub fn extension_root(fields: &[(&[u8], &[u8])]) -> [u8; 32] {
    if fields.is_empty() {
        return blake2b256(&[]);
    }
    let leaves: Vec<Vec<u8>> = fields
        .iter()
        .map(|(k, v)| {
            let mut leaf = Vec::with_capacity(1 + k.len() + v.len());
            leaf.push(k.len() as u8);
            leaf.extend_from_slice(k);
            leaf.extend_from_slice(v);
            leaf
        })
        .collect();
    let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    merkle_tree_root(&refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity -----

    #[test]
    fn merkle_root_empty_input_pinned_to_blake2b_of_empty_bytes() {
        let root = merkle_tree_root(&[]);
        let expected = blake2b256(&[]);
        assert_eq!(root, expected);
        // Pinned against scorex `Algos.emptyMerkleTreeRoot`:
        // hash(LeafData @@ Array[Byte]()) = Blake2b256(empty).
        assert_eq!(
            hex::encode(root),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    // ----- happy path -----

    #[test]
    fn merkle_root_single_leaf_pads_with_empty_sibling() {
        let data = b"hello";
        let root = merkle_tree_root(&[data]);
        // Single leaf: InternalNode(Leaf(data), EmptyNode)
        // = blake2b(0x01 ++ leaf_hash(data)) since EmptyNode.hash = []
        let lh = leaf_hash(data);
        let mut input = vec![INTERNAL_NODE_PREFIX];
        input.extend_from_slice(&lh);
        let expected = blake2b256(&input);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_two_leaves_is_internal_hash_of_leaf_hashes() {
        let a = b"aaa";
        let b_data = b"bbb";
        let root = merkle_tree_root(&[a, b_data]);
        let la = leaf_hash(a);
        let lb = leaf_hash(b_data);
        let expected = internal_hash(&la, &lb);
        assert_eq!(root, expected);
    }

    #[test]
    fn proof_single_leaf_has_one_empty_sibling_level() {
        let a = b"only";
        let proof = merkle_proof_by_index(&[a], 0).expect("must produce proof");
        assert_eq!(proof.leaf_data, a.to_vec());
        assert_eq!(
            proof.levels.len(),
            1,
            "single-leaf tree must produce one level"
        );
        let (sibling, side) = &proof.levels[0];
        assert!(
            sibling.is_empty(),
            "single-leaf sibling must be empty bytes"
        );
        assert_eq!(
            *side, 0,
            "leaf at index 0 has left position; sibling on right"
        );

        let root = merkle_tree_root(&[a]);
        assert!(
            merkle_proof_verify(&proof, &root),
            "proof must verify against canonical root"
        );
    }

    #[test]
    fn proof_two_leaves_at_index_0() {
        let a = b"left";
        let b = b"right";
        let proof = merkle_proof_by_index(&[a, b], 0).expect("must produce proof");
        assert_eq!(proof.leaf_data, a.to_vec());
        assert_eq!(proof.levels.len(), 1);
        let (sibling, side) = &proof.levels[0];
        assert_eq!(sibling.as_slice(), &leaf_hash(b)[..]);
        assert_eq!(*side, 0);
        let root = merkle_tree_root(&[a, b]);
        assert!(merkle_proof_verify(&proof, &root));
    }

    #[test]
    fn proof_two_leaves_at_index_1() {
        let a = b"left";
        let b = b"right";
        let proof = merkle_proof_by_index(&[a, b], 1).expect("must produce proof");
        assert_eq!(proof.leaf_data, b.to_vec());
        let (sibling, side) = &proof.levels[0];
        assert_eq!(sibling.as_slice(), &leaf_hash(a)[..]);
        assert_eq!(*side, 1, "leaf at index 1 is right child; sibling on left");
        let root = merkle_tree_root(&[a, b]);
        assert!(merkle_proof_verify(&proof, &root));
    }

    #[test]
    fn proof_three_leaves_each_index_verifies() {
        let leaves = [b"aaa".as_slice(), b"bbb".as_slice(), b"ccc".as_slice()];
        let root = merkle_tree_root(&leaves);
        for i in 0..leaves.len() {
            let proof = merkle_proof_by_index(&leaves, i).expect("proof");
            assert!(
                merkle_proof_verify(&proof, &root),
                "proof at index {i} must verify"
            );
        }
        // 3 leaves → padded to 4 → depth 2 → 2 levels.
        let proof = merkle_proof_by_index(&leaves, 0).expect("proof");
        assert_eq!(proof.levels.len(), 2);
    }

    #[test]
    fn proof_five_leaves_each_index_verifies() {
        let leaves = [
            b"00".as_slice(),
            b"11".as_slice(),
            b"22".as_slice(),
            b"33".as_slice(),
            b"44".as_slice(),
        ];
        let root = merkle_tree_root(&leaves);
        for i in 0..leaves.len() {
            let proof = merkle_proof_by_index(&leaves, i).expect("proof");
            assert!(
                merkle_proof_verify(&proof, &root),
                "proof at index {i} must verify"
            );
            // 5 leaves → padded to 8 → depth 3 → 3 levels.
            assert_eq!(proof.levels.len(), 3);
        }
    }

    #[test]
    fn root_unchanged_after_proof_module_addition() {
        // Sanity: the new code did not touch merkle_tree_root. Pin a few
        // known values to guard against accidental drift.
        let known = blake2b256(&[]);
        assert_eq!(merkle_tree_root(&[]), known);

        let a = b"alpha";
        let b = b"beta";
        let expected = internal_hash(&leaf_hash(a), &leaf_hash(b));
        assert_eq!(merkle_tree_root(&[a, b]), expected);
    }

    #[test]
    fn merkle_root_three_leaves_pairs_third_with_empty_node() {
        let a = b"aaa";
        let b_data = b"bbb";
        let c = b"ccc";
        let root = merkle_tree_root(&[a, b_data, c]);

        let la = leaf_hash(a);
        let lb = leaf_hash(b_data);
        let lc = leaf_hash(c);

        // Level 1: [InternalNode(la, lb), InternalNode(lc, EmptyNode)]
        let left = internal_hash(&la, &lb);
        let mut right_input = vec![INTERNAL_NODE_PREFIX];
        right_input.extend_from_slice(&lc);
        let right = blake2b256(&right_input);

        // Level 2: InternalNode(left, right) — even pair
        let expected = internal_hash(&left, &right);
        assert_eq!(root, expected);
    }

    // ----- error paths -----

    #[test]
    fn proof_out_of_range_returns_none() {
        let leaves = [b"x".as_slice(), b"y".as_slice()];
        assert!(merkle_proof_by_index(&leaves, 2).is_none());
        assert!(merkle_proof_by_index(&[], 0).is_none());
    }

    // ----- properties -----

    proptest::proptest! {
        /// Structural Merkle invariant: for any non-empty leaf list of
        /// up to 128 leaves, every leaf's proof verifies against the
        /// root. This catches drift in the proof builder, root
        /// computation, or verification path that would break the
        /// "every honest leaf is provable" guarantee.
        ///
        /// Leaf payloads are arbitrary 0..=64-byte byte strings —
        /// covers the variable-length tx-id-style and witness-id-style
        /// inputs the production `transactions_root` builds over.
        ///
        /// Determinism (same input → same root) is separately implied
        /// because `blake2b256` is a pure function over the reduction
        /// stack and this property asserts the proof matches the root
        /// derived in the same call.
        #[test]
        fn proptest_merkle_proof_for_every_leaf_verifies_against_root(
            leaves in proptest::collection::vec(
                proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=64),
                1..=128,
            ),
        ) {
            let leaf_refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();
            let root = merkle_tree_root(&leaf_refs);
            for i in 0..leaves.len() {
                let proof = merkle_proof_by_index(&leaf_refs, i)
                    .expect("every in-range index must yield a proof");
                proptest::prop_assert!(
                    merkle_proof_verify(&proof, &root),
                    "proof for index {} of {} must verify against root", i, leaves.len(),
                );
            }
        }
    }
}
