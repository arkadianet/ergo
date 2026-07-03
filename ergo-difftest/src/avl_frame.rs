//! Shared AVL+ batch-proof frame layout used by BOTH the Rust harness
//! (`ergo_sigma::avl::AvlVerifier`) and the Scala oracle sidecar
//! (`scripts/jvm_serde_oracle/ErgoSerdeOracle.scala`, `verify_avl` surface).
//!
//! Defined ONCE so the exact same bytes drive both implementations; any
//! field-order or encoding discrepancy shows up immediately as a framing
//! error on one side rather than a silent parity gap.
//!
//! ## Wire layout (do NOT change without updating the Scala twin)
//!
//! ```text
//! startingDigest(33)                       -- raw bytes: 32 hash + 1 height
//! ‖ keyLen(u8)                             -- fixed key length for this tree
//! ‖ valueLenOpt(1 tag: 0=None / 1=Some)   -- if 1: followed by 1 byte
//! ‖ proofLen(vlq/u32)                      -- unsigned LEB128
//! ‖ proof[proofLen]
//! ‖ opCount(vlq/u32)
//! ‖ [opTag(u8: 0=Lookup 1=Insert 2=Update 3=Remove)
//!    ‖ key[keyLen]
//!    ‖ (Insert/Update only: valLen(vlq/u32) ‖ val[valLen])]*
//! ```
//!
//! The `valueLenOpt` header field is the `BatchAVLVerifier` construction
//! parameter (fixed vs variable value length); it is NOT a per-op field.
//! For Insert/Update operations the value is always preceded by a VLQ
//! length even when `valueLenOpt` is `Some(n)`, so the decoder is
//! self-contained and never needs to look ahead.

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;

/// An operation to apply to the AVL tree during batch-proof verification.
#[derive(Debug, Clone, PartialEq)]
pub enum AvlOp {
    /// Lookup: verify the key is (or is not) in the tree.
    Lookup { key: Vec<u8> },
    /// Insert: add a new key-value pair; proof covers the insertion path.
    Insert { key: Vec<u8>, value: Vec<u8> },
    /// Update: overwrite the value of an existing key.
    Update { key: Vec<u8>, value: Vec<u8> },
    /// Remove: delete the key from the tree.
    Remove { key: Vec<u8> },
}

/// A framed AVL+ batch proof, ready for verification.
#[derive(Debug, Clone, PartialEq)]
pub struct AvlFrame {
    /// 33-byte tree digest at the start of the operation batch.
    pub starting_digest: [u8; 33],
    /// Fixed key length (bytes) for all keys in this tree.
    pub key_len: u8,
    /// Fixed value length, or `None` for variable-length values.
    pub value_len_opt: Option<u8>,
    /// Serialized batch proof bytes (witnesses the operations below).
    pub proof: Vec<u8>,
    /// Ordered list of operations to verify against the proof.
    pub ops: Vec<AvlOp>,
}

impl AvlFrame {
    /// Encode the frame to wire bytes using the shared layout above.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = VlqWriter::new();
        w.put_bytes(&self.starting_digest);
        w.put_u8(self.key_len);
        match self.value_len_opt {
            None => w.put_u8(0),
            Some(n) => {
                w.put_u8(1);
                w.put_u8(n);
            }
        }
        w.put_u32(self.proof.len() as u32);
        w.put_bytes(&self.proof);
        w.put_u32(self.ops.len() as u32);
        for op in &self.ops {
            match op {
                AvlOp::Lookup { key } => {
                    w.put_u8(0);
                    w.put_bytes(key);
                }
                AvlOp::Insert { key, value } => {
                    w.put_u8(1);
                    w.put_bytes(key);
                    w.put_u32(value.len() as u32);
                    w.put_bytes(value);
                }
                AvlOp::Update { key, value } => {
                    w.put_u8(2);
                    w.put_bytes(key);
                    w.put_u32(value.len() as u32);
                    w.put_bytes(value);
                }
                AvlOp::Remove { key } => {
                    w.put_u8(3);
                    w.put_bytes(key);
                }
            }
        }
        w.result()
    }

    /// Decode an [`AvlFrame`] from wire bytes.
    ///
    /// Returns `Err` with a human-readable message on any framing violation
    /// (truncation, bad tag, etc.).  A framing error is an oracle/harness
    /// problem, not a node finding — the oracle returns `ERR`, not `REJECT`.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = VlqReader::new(bytes);

        let starting_digest = r
            .get_array::<33>()
            .map_err(|e| format!("startingDigest: {e:?}"))?;

        let key_len = r.get_u8().map_err(|e| format!("keyLen: {e:?}"))?;

        let tag = r.get_u8().map_err(|e| format!("valueLenOpt tag: {e:?}"))?;
        let value_len_opt = match tag {
            0 => None,
            1 => Some(
                r.get_u8()
                    .map_err(|e| format!("valueLenOpt value: {e:?}"))?,
            ),
            _ => return Err(format!("unknown valueLenOpt tag {tag}: expected 0 or 1")),
        };

        let proof_len = r.get_u32_exact().map_err(|e| format!("proofLen: {e:?}"))? as usize;
        let proof = r
            .get_bytes(proof_len)
            .map_err(|e| format!("proof[{proof_len}]: {e:?}"))?
            .to_vec();

        let op_count = r.get_u32_exact().map_err(|e| format!("opCount: {e:?}"))? as usize;
        // Bound the pre-allocation: `op_count` is untrusted, so a malformed frame
        // could otherwise request a multi-GB `Vec` before a single op is read. The
        // loop still reads `op_count` ops and errors on buffer exhaustion.
        let mut ops = Vec::with_capacity(op_count.min(1 << 12));
        for i in 0..op_count {
            let op_tag = r.get_u8().map_err(|e| format!("op[{i}] tag: {e:?}"))?;
            let key = r
                .get_bytes(key_len as usize)
                .map_err(|e| format!("op[{i}] key: {e:?}"))?
                .to_vec();
            let op = match op_tag {
                0 => AvlOp::Lookup { key },
                1 => {
                    let val_len = r
                        .get_u32_exact()
                        .map_err(|e| format!("op[{i}] valLen: {e:?}"))?
                        as usize;
                    let value = r
                        .get_bytes(val_len)
                        .map_err(|e| format!("op[{i}] val: {e:?}"))?
                        .to_vec();
                    AvlOp::Insert { key, value }
                }
                2 => {
                    let val_len = r
                        .get_u32_exact()
                        .map_err(|e| format!("op[{i}] valLen: {e:?}"))?
                        as usize;
                    let value = r
                        .get_bytes(val_len)
                        .map_err(|e| format!("op[{i}] val: {e:?}"))?
                        .to_vec();
                    AvlOp::Update { key, value }
                }
                3 => AvlOp::Remove { key },
                _ => return Err(format!("op[{i}] unknown tag {op_tag}")),
            };
            ops.push(op);
        }

        Ok(AvlFrame {
            starting_digest,
            key_len,
            value_len_opt,
            proof,
            ops,
        })
    }
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_roundtrip(frame: &AvlFrame) {
        let encoded = frame.encode();
        let decoded = AvlFrame::decode(&encoded).expect("decode should succeed");
        assert_eq!(
            &decoded, frame,
            "round-trip must produce identical AvlFrame"
        );
        // Re-encode must be byte-stable.
        assert_eq!(decoded.encode(), encoded, "re-encode must be a fixed point");
    }

    /// Empty op list, no value length — the minimal valid frame.
    #[test]
    fn roundtrip_empty_ops_no_value_len() {
        frame_roundtrip(&AvlFrame {
            starting_digest: [0xABu8; 33],
            key_len: 32,
            value_len_opt: None,
            proof: vec![0x01, 0x02, 0x03],
            ops: vec![],
        });
    }

    /// Fixed-value-length tree, all four op variants present.
    #[test]
    fn roundtrip_all_op_variants_fixed_value_len() {
        let key = vec![0x11u8; 32];
        let value = vec![0xABu8, 0xCD];
        frame_roundtrip(&AvlFrame {
            starting_digest: [0x42u8; 33],
            key_len: 32,
            value_len_opt: Some(2),
            proof: b"fake-proof".to_vec(),
            ops: vec![
                AvlOp::Lookup { key: key.clone() },
                AvlOp::Insert {
                    key: key.clone(),
                    value: value.clone(),
                },
                AvlOp::Update {
                    key: key.clone(),
                    value: value.clone(),
                },
                AvlOp::Remove { key: key.clone() },
            ],
        });
    }

    /// Variable-value-length tree with Insert and Update having different
    /// value lengths — exercises the per-op valLen field.
    #[test]
    fn roundtrip_variable_value_len_different_sizes() {
        frame_roundtrip(&AvlFrame {
            starting_digest: [0u8; 33],
            key_len: 8,
            value_len_opt: None,
            proof: vec![0xFF; 20],
            ops: vec![
                AvlOp::Insert {
                    key: vec![1u8; 8],
                    value: vec![0x01],
                },
                AvlOp::Update {
                    key: vec![2u8; 8],
                    value: vec![0xBE, 0xEF, 0xCA, 0xFE],
                },
                AvlOp::Lookup { key: vec![3u8; 8] },
                AvlOp::Remove { key: vec![4u8; 8] },
            ],
        });
    }

    /// Truncated input must return `Err`, not panic.
    #[test]
    fn decode_truncated_returns_err() {
        let frame = AvlFrame {
            starting_digest: [0u8; 33],
            key_len: 4,
            value_len_opt: None,
            proof: vec![0x01, 0x02],
            ops: vec![AvlOp::Lookup { key: vec![0u8; 4] }],
        };
        let encoded = frame.encode();
        // Every proper prefix must fail, not panic.
        for n in 1..encoded.len() {
            let result = AvlFrame::decode(&encoded[..n]);
            assert!(result.is_err(), "expected Err on prefix[..{n}], got Ok");
        }
    }

    /// Unknown valueLenOpt tag must return `Err`.
    #[test]
    fn decode_unknown_value_len_tag_returns_err() {
        let mut encoded = AvlFrame {
            starting_digest: [0u8; 33],
            key_len: 4,
            value_len_opt: None,
            proof: vec![],
            ops: vec![],
        }
        .encode();
        // Byte 34 = valueLenOpt tag (after 33 startingDigest bytes + 1 keyLen byte).
        encoded[34] = 2;
        assert!(AvlFrame::decode(&encoded).is_err());
    }

    /// Unknown op tag must return `Err`.
    #[test]
    fn decode_unknown_op_tag_returns_err() {
        let mut encoded = AvlFrame {
            starting_digest: [0u8; 33],
            key_len: 4,
            value_len_opt: None,
            proof: vec![],
            ops: vec![AvlOp::Lookup { key: vec![0u8; 4] }],
        }
        .encode();
        // The op tag byte follows the opCount (1 byte after header + proof).
        // Find it by counting: 33 + 1 + 1 (None tag) + 1 (proofLen=0) + 1 (opCount=1) = byte 36.
        let op_tag_pos = 33 + 1 + 1 + 1 + 1;
        encoded[op_tag_pos] = 0xFF;
        assert!(AvlFrame::decode(&encoded).is_err());
    }

    /// Generate the DoS-class trigger for bug #6 (valid-but-wrong AVL proof).
    ///
    /// A LOOKUP proof for `key_a` is supplied to a verifier that then attempts
    /// a REMOVE of `key_a`.  On unguarded upstream: op-time panic.
    /// On guarded (`AvlVerifier`): `Err(())` → `Outcome::Rejected`.
    ///
    /// This test generates and prints the trigger hex so it can be pinned in
    /// the manifest as `trigger_hex`.  It does not assert the hex value itself
    /// (the bytes depend on `ergo_avltree_rust` internals); instead it asserts
    /// the structural invariant that the guarded verifier rejects the trigger
    /// without panicking.
    #[test]
    fn avl_panic_trigger_guarded_rejects_not_panics() {
        use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
        use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
        use ergo_avltree_rust::batch_node::{AVLTree, Node, NodeHeader};
        use ergo_avltree_rust::operation::{KeyValue, Operation};
        use ergo_sigma::avl::AvlVerifier;

        fn new_prover() -> BatchAVLProver {
            BatchAVLProver::new(
                AVLTree::new(
                    |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
                    32,
                    None,
                ),
                true,
            )
        }

        let key_a = [0x01u8; 32];
        let key_b = [0x0Cu8; 32]; // 12u8

        // Build the prover tree with key_a and key_b inserted.
        let mut prover = new_prover();
        for k in [key_a, key_b] {
            prover
                .perform_one_operation(&Operation::Insert(KeyValue {
                    key: bytes::Bytes::from(k.to_vec()),
                    value: bytes::Bytes::from(vec![0xABu8]),
                }))
                .expect("seed insert");
        }
        let _ = prover.generate_proof();
        let parent_digest: Vec<u8> = prover.digest().expect("prover digest").to_vec();

        // Generate a LOOKUP proof for key_a on an identical prover.
        let mut lp = new_prover();
        for k in [key_a, key_b] {
            lp.perform_one_operation(&Operation::Insert(KeyValue {
                key: bytes::Bytes::from(k.to_vec()),
                value: bytes::Bytes::from(vec![0xABu8]),
            }))
            .expect("seed lp insert");
        }
        let _ = lp.generate_proof();
        lp.perform_one_operation(&Operation::Lookup(bytes::Bytes::from(key_a.to_vec())))
            .expect("prover lookup");
        let lookup_proof: Vec<u8> = lp.generate_proof().to_vec();

        // Build the avl_frame: startingDigest=parent, proof=lookupProof, op=Remove(key_a).
        let mut digest_arr = [0u8; 33];
        digest_arr.copy_from_slice(&parent_digest);
        let frame = AvlFrame {
            starting_digest: digest_arr,
            key_len: 32,
            value_len_opt: None,
            proof: lookup_proof,
            ops: vec![AvlOp::Remove {
                key: key_a.to_vec(),
            }],
        };

        let encoded = frame.encode();
        let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();

        // Print so CI or a developer running this test can see the trigger hex.
        eprintln!("avl_panic_trigger_hex={hex}");

        // Round-trip.
        let decoded = AvlFrame::decode(&encoded).expect("must decode");
        assert_eq!(decoded, frame);

        // Structural assertion: the GUARDED verifier must reject, not panic.
        let mut verifier = AvlVerifier::new(&frame.starting_digest, &frame.proof, 32, None)
            .expect("construction from valid-shaped proof");
        let result = verifier.remove(&key_a);
        assert_eq!(
            result,
            Err(()),
            "guarded verifier must return Err on wrong-proof Remove, not panic"
        );
        assert_eq!(
            verifier.digest(),
            None,
            "verifier must be poisoned after a caught op-time panic"
        );
    }
}
