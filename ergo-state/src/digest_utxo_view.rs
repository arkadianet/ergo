//! Proof-backed `UtxoView` for Mode 5 (digest verifier) block
//! validation.
//!
//! A digest node stores no box arena, so it cannot resolve a
//! transaction's input/data-input boxes by lookup. Instead it resolves
//! them from the block's ADProofs: verifying the proof yields the OLD
//! VALUES of every box the proof touches (the spent inputs + the
//! pre-existing data inputs — see
//! [`crate::digest_apply::DigestProofVerifier::apply_block_resolving_boxes`]).
//! Those, combined with the block's own outputs, are exactly the box
//! set Scala's `DigestState.validateTransactions` builds:
//!
//! ```text
//! knownBoxes = transactions.flatMap(_.outputs) ++ boxesFromProofs
//! ```
//!
//! The block's outputs cover inputs/data-inputs that reference a box
//! created earlier in the same block (which the parent-state proof does
//! not witness). Full transaction validation (scripts, amounts) then
//! runs against this view, identically to the UTXO backend — only the
//! box source differs.
//!
//! `#![allow(dead_code)]`: the view is consumed by the digest-mode
//! block-processing path wired in a later phase; no production caller
//! reaches it yet.
#![allow(dead_code)]

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::transaction::{transaction_id, Transaction};

use crate::digest_apply::ResolvedBoxes;
use crate::store::StateError;

/// A [`ergo_validation::UtxoView`] backed by ADProofs-resolved boxes
/// plus the block's own outputs.
#[derive(Debug)]
pub struct DigestUtxoView {
    boxes: HashMap<[u8; 32], ErgoBox>,
}

impl DigestUtxoView {
    /// Build the view from the proof-witnessed boxes (`box_id ->
    /// serialized bytes`, from `apply_block_resolving_boxes`) and the
    /// block's raw transactions (whose outputs are added so in-block
    /// box chaining resolves). Mirrors Scala's `knownBoxes`.
    ///
    /// A box id appearing in both sets resolves to the same box (the
    /// proof's old value and the creating output are byte-identical),
    /// so insertion order does not matter.
    pub fn new(resolved: &ResolvedBoxes, transactions: &[Transaction]) -> Result<Self, StateError> {
        let mut boxes = HashMap::with_capacity(resolved.len() + transactions.len() * 2);

        // Proof-witnessed boxes: spent inputs + pre-existing data inputs.
        for (box_id, bytes) in resolved {
            let parsed = read_ergo_box(&mut VlqReader::new(bytes)).map_err(|e| {
                StateError::Serialization(format!(
                    "digest UtxoView: proof box {} failed to parse: {e:?}",
                    hex::encode(box_id),
                ))
            })?;
            boxes.insert(*box_id, parsed);
        }

        // The block's own outputs (all transactions, in block order) —
        // covers inputs/data-inputs that reference a box created earlier
        // in the same block.
        for tx in transactions {
            let tx_id = transaction_id(tx)
                .map_err(|e| StateError::Serialization(format!("digest UtxoView: tx id: {e:?}")))?;
            for (index, candidate) in tx.output_candidates.iter().enumerate() {
                let ergo_box = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id,
                    index: index as u16,
                };
                let id = ergo_box.box_id().map_err(|e| {
                    StateError::Serialization(format!("digest UtxoView: output box id: {e:?}"))
                })?;
                boxes.insert(*id.as_bytes(), ergo_box);
            }
        }

        Ok(Self { boxes })
    }

    /// Number of distinct boxes the view can resolve.
    pub fn len(&self) -> usize {
        self.boxes.len()
    }

    /// Whether the view resolves no boxes.
    pub fn is_empty(&self) -> bool {
        self.boxes.is_empty()
    }
}

impl ergo_validation::UtxoView for DigestUtxoView {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.boxes.get(box_id.as_bytes()).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_validation::UtxoView;

    // ----- helpers -----

    #[derive(serde::Deserialize)]
    struct BoxVector {
        #[serde(rename = "boxId")]
        box_id: String,
        bytes: String,
    }

    fn arr32(h: &str) -> [u8; 32] {
        let v = hex::decode(h).expect("hex32");
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    // ----- happy path -----

    #[test]
    fn resolves_real_mainnet_boxes_by_id() {
        // Real mainnet box bytes (the same vectors ergo-ser round-trips)
        // stand in for the proof-witnessed boxes: the view must parse
        // each via `read_ergo_box` and return it by id.
        let json = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/mainnet/boxes_recent.json"
        ))
        .expect("boxes_recent.json");
        let vectors: Vec<BoxVector> = serde_json::from_str(&json).expect("parse vectors");
        assert!(!vectors.is_empty(), "no box vectors");

        let resolved: ResolvedBoxes = vectors
            .iter()
            .map(|v| (arr32(&v.box_id), hex::decode(&v.bytes).expect("box bytes")))
            .collect();

        let view = DigestUtxoView::new(&resolved, &[]).expect("build view");
        for (box_id, _) in &resolved {
            let resolved_box = view
                .get_box(&Digest32::from_bytes(*box_id))
                .unwrap_or_else(|| panic!("box {} not resolvable", hex::encode(box_id)));
            // The parsed box re-derives its own id — proves the bytes
            // parsed into a faithful ErgoBox, not just a blob.
            assert_eq!(
                resolved_box.box_id().expect("box id").as_bytes(),
                box_id,
                "resolved box does not round-trip its id",
            );
        }
    }

    // ----- error paths -----

    #[test]
    fn unknown_box_id_resolves_to_none() {
        let view = DigestUtxoView::new(&Vec::new(), &[]).expect("empty view");
        assert!(view.is_empty());
        assert!(view.get_box(&Digest32::from_bytes([0x11; 32])).is_none());
    }

    #[test]
    fn malformed_proof_box_bytes_error() {
        let resolved: ResolvedBoxes = vec![([0x22u8; 32], vec![0xFF, 0xFF, 0xFF])];
        let err = DigestUtxoView::new(&resolved, &[]).expect_err("garbage box must error");
        assert!(matches!(err, StateError::Serialization(_)), "got {err:?}");
    }
}
