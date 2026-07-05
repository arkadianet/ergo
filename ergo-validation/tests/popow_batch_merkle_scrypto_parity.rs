//! BatchMerkleProof construction + wire + verification parity against
//! scrypto, on SYNTHETIC edge shapes the real-chain fixtures can't
//! cover: single-leaf tree, all-leaf proofs, odd trees at multiple
//! levels (n=3,5,7,13,17), right-edge leaves, sparse subsets. Expected
//! values captured via scala-cli (scrypto MerkleTree.proofByIndices +
//! BatchMerkleProofSerializer, ergo-core 6.0.2 deps, 2026-07-05):
//! `test-vectors/mainnet/nipopow/batch_merkle_shapes_scala.txt`, lines
//! of `n|indices|root|proof_hex|valid`. Leaf i = 33 bytes of (i+1).
//!
//! Asserts, per case: (1) our construction serializes byte-identically
//! to scrypto's; (2) our verifier accepts the scrypto proof against the
//! scrypto root; (3) our recomputed root equals scrypto's.

use ergo_crypto::merkle::{merkle_proof_by_indices, merkle_tree_root};
use ergo_ser::batch_merkle_proof::{
    deserialize_batch_merkle_proof, serialize_batch_merkle_proof, BatchMerkleProof, ProofEntry,
    Side,
};
use ergo_validation::popow::verify_batch_merkle_proof;

#[test]
fn synthetic_shapes_match_scrypto_byte_for_byte() {
    let raw =
        std::fs::read_to_string("../test-vectors/mainnet/nipopow/batch_merkle_shapes_scala.txt")
            .expect("oracle fixture");
    let mut cases = 0;
    for line in raw.lines() {
        let mut parts = line.split('|');
        let n: usize = parts.next().unwrap().parse().unwrap();
        let indices: Vec<u32> = parts
            .next()
            .unwrap()
            .split(',')
            .map(|s| s.parse().unwrap())
            .collect();
        let root_hex = parts.next().unwrap();
        let proof_hex = parts.next().unwrap();
        assert_eq!(
            parts.next().unwrap(),
            "true",
            "oracle proof must self-verify"
        );

        let leaves: Vec<Vec<u8>> = (0..n).map(|i| vec![(i + 1) as u8; 33]).collect();
        let leaf_refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();

        // (3) root parity
        let our_root = merkle_tree_root(&leaf_refs);
        assert_eq!(hex::encode(our_root), root_hex, "root n={n}");

        // (1) construction + wire parity
        let (idx, proofs) = merkle_proof_by_indices(&leaf_refs, &indices)
            .unwrap_or_else(|| panic!("construction n={n} idx={indices:?}"));
        let ours = BatchMerkleProof {
            indices: idx,
            proofs: proofs
                .into_iter()
                .map(|e| ProofEntry {
                    digest: e.digest,
                    side: if e.side == 0 { Side::Left } else { Side::Right },
                })
                .collect(),
        };
        let our_bytes = serialize_batch_merkle_proof(&ours);
        assert_eq!(
            hex::encode(&our_bytes),
            proof_hex,
            "wire bytes n={n} idx={indices:?}"
        );

        // (2) verification of the scrypto-emitted proof
        let scrypto_bytes = hex::decode(proof_hex).unwrap();
        let scrypto_proof = deserialize_batch_merkle_proof(&scrypto_bytes).unwrap();
        let mut root = [0u8; 32];
        hex::decode_to_slice(root_hex, &mut root).unwrap();
        assert!(
            verify_batch_merkle_proof(&scrypto_proof, &root),
            "verify n={n} idx={indices:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 20, "all oracle cases exercised");
}
