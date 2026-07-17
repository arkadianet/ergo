//! Receive-time section-id verification.
//!
//! Free function, fully independent of [`SyncCoordinator`]'s state —
//! kept out of the coordinator path so coordinator tests can drive
//! assembly flow with synthetic fixtures without canonical wire bytes.
//!
//! [`SyncCoordinator`]: super::SyncCoordinator

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};

/// Verify that the bytes received for `modifier_id` actually re-hash to
/// that modifier_id. Mirrors Scala
/// `ErgoNodeViewSynchronizer.parseModifiers:801-813` — the receive-time
/// check that prevents a peer from claiming "here's the bytes for ID X"
/// while sending bytes whose canonical content recomputes a different
/// ID. Correctness at apply time would also catch this; doing it on
/// receive lets us penalize the lying peer immediately instead of
/// after we've persisted bad bytes and walked them through the
/// assembly path.
///
/// Returns `Ok(())` for unknown section types — those don't have a
/// canonical receive-time recomputation rule and are filtered out
/// upstream by the delivery tracker (unsolicited modifiers → Spam).
///
/// Caller is `ergo-node/src/node/messaging.rs`'s `CODE_MODIFIER` arm,
/// which invokes this before passing bytes to
/// [`SyncCoordinator::on_modifier_received`]. Kept out of the
/// coordinator path so coordinator tests can drive assembly flow with
/// synthetic fixtures without canonical wire bytes.
pub fn verify_section_modifier_id(
    type_id: u8,
    modifier_id: &[u8; 32],
    bytes: &[u8],
) -> Result<(), String> {
    let mut r = VlqReader::new(bytes);
    let candidates: Vec<[u8; 32]> = match type_id {
        TYPE_BLOCK_TRANSACTIONS => {
            let bt = ergo_ser::block_transactions::read_block_transactions(&mut r)
                .map_err(|e| format!("BlockTransactions parse: {e:?}"))?;
            if r.remaining() != 0 {
                return Err(format!(
                    "trailing bytes after BlockTransactions ({} extra)",
                    r.remaining(),
                ));
            }
            let tx_ids: Result<Vec<[u8; 32]>, _> = bt
                .transactions
                .iter()
                .map(|tx| ergo_ser::transaction::transaction_id(tx).map(|id| *id.as_bytes()))
                .collect();
            let tx_ids = tx_ids.map_err(|e| format!("transaction_id: {e:?}"))?;
            let tx_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
            // v1 (pre-Autolykos-v2, height < 417_792): merkle root over
            // tx_ids only. v2+: root over `tx_ids ++ witness_ids`, where
            // each witness_id is `blake2b256(concatenated_input_proofs)
            // .drop(1)` per `ergo-validation/src/block.rs:472-488`. The
            // parsed `BlockTransactions` struct doesn't expose the block
            // version (the v2+ wire marker is consumed by the reader),
            // so compute both candidate roots and accept whichever
            // matches — the alternative would require re-parsing the
            // version marker or threading the header version through
            // the caller. Cost is one extra merkle round on canonical
            // v1 sections, which haven't appeared since 2020.
            let v1_root = ergo_crypto::merkle::transactions_root(&tx_refs, None);
            let witness_data: Vec<Vec<u8>> = bt
                .transactions
                .iter()
                .map(|tx| {
                    let mut proofs = Vec::new();
                    for input in &tx.inputs {
                        proofs.extend_from_slice(&input.spending_proof.proof);
                    }
                    let h = ergo_crypto::autolykos::common::blake2b256(&proofs);
                    h[1..].to_vec()
                })
                .collect();
            let witness_refs: Vec<&[u8]> = witness_data.iter().map(|w| w.as_slice()).collect();
            let v2_root = ergo_crypto::merkle::transactions_root(&tx_refs, Some(&witness_refs));
            vec![
                compute_section_id(TYPE_BLOCK_TRANSACTIONS, bt.header_id.as_bytes(), &v1_root),
                compute_section_id(TYPE_BLOCK_TRANSACTIONS, bt.header_id.as_bytes(), &v2_root),
            ]
        }
        TYPE_EXTENSION => {
            let ext = ergo_ser::extension::read_extension(&mut r)
                .map_err(|e| format!("Extension parse: {e:?}"))?;
            if r.remaining() != 0 {
                return Err(format!(
                    "trailing bytes after Extension ({} extra)",
                    r.remaining(),
                ));
            }
            let kv: Vec<(&[u8], &[u8])> = ext
                .fields
                .iter()
                .map(|f| (f.key.as_slice(), f.value.as_slice()))
                .collect();
            let root = ergo_crypto::merkle::extension_root(&kv);
            vec![compute_section_id(
                TYPE_EXTENSION,
                ext.header_id.as_bytes(),
                &root,
            )]
        }
        TYPE_AD_PROOFS => {
            let ap = ergo_ser::ad_proofs::read_ad_proofs(&mut r)
                .map_err(|e| format!("ADProofs parse: {e:?}"))?;
            if r.remaining() != 0 {
                return Err(format!(
                    "trailing bytes after ADProofs ({} extra)",
                    r.remaining(),
                ));
            }
            let digest = *blake2b256(&ap.proof_bytes).as_bytes();
            vec![compute_section_id(
                TYPE_AD_PROOFS,
                ap.header_id.as_bytes(),
                &digest,
            )]
        }
        _ => {
            // Reject unknown section types so a peer can't escape the
            // receive-time check by claiming an arbitrary high
            // `type_id` that happens to pass `is_block_section`'s
            // `>= 50` floor. Caller is expected to gate this function
            // on {102, 104, 108} for canonical traffic.
            return Err(format!("unknown section type {type_id}"));
        }
    };
    if candidates.iter().any(|c| c == modifier_id) {
        Ok(())
    } else {
        Err(format!(
            "section_id mismatch: claimed {} recomputed candidates {:?}",
            hex::encode(modifier_id),
            candidates.iter().map(hex::encode).collect::<Vec<_>>(),
        ))
    }
}
