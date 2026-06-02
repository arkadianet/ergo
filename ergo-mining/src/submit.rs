//! Block-application path for accepted mining solutions.
//!
//! v12 §6 step 6 — the executor-side gate. Runs **inside the action
//! loop** so reads of `chain_state` are serialized with applies, closing
//! the TOCTOU window the HTTP-side step-4 check can't.
//!
//! Wire-up at the node level: hold a
//! `mpsc::Sender<MiningSubmitRequest>` on the API task side, drain it
//! once per tick in the main loop just like `submit_rx` for
//! `SubmitRequest`, and call [`apply_mined_block`] inside the drain
//! arm.

use ergo_primitives::writer::VlqWriter;
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::extension::{write_extension, Extension, ExtensionField};
use ergo_ser::header::serialize_header;
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::store::StateStore;
use thiserror::Error;
use tokio::sync::oneshot;

use crate::solution::SubmittedBlock;

/// Request shipped from the API task to the main loop. The main loop
/// drains it, calls [`apply_mined_block`], and replies through `reply`.
#[derive(Debug)]
pub struct MiningSubmitRequest {
    /// Block-application payload, packaged by the API-side pre-check.
    pub block: SubmittedBlock,
    /// One-shot reply channel. `Ok(())` on apply success, `Err(reason)`
    /// otherwise.
    pub reply: oneshot::Sender<Result<(), MiningSubmitError>>,
}

/// Failure modes for the executor-side mining apply.
#[derive(Debug, Error)]
pub enum MiningSubmitError {
    /// Best-full-block flipped between the API pre-check and the
    /// executor pickup. v12 §6 step 6: the authoritative TOCTOU close.
    #[error(
        "stale candidate (best-full flipped): expected parent {expected}, observed {observed}"
    )]
    StaleParent { expected: String, observed: String },
    /// Section serialization failed (header / transactions / extension /
    /// ad-proofs).
    #[error("serialize section: {0}")]
    SerializeSection(String),
    /// Section persistence failed (redb write or wrong type).
    #[error("persist section: {0}")]
    PersistSection(String),
    /// Block validation or apply failed downstream.
    #[error("apply block: {0}")]
    Apply(String),
}

/// Persist the three block-sections of an accepted mining solution
/// under their canonical modifier ids and type bytes. Performs the
/// authoritative `parent_id` recheck (v12 §6 step 6, the consensus-
/// bearing TOCTOU close) before writing anything.
///
/// Header persistence + HEADER_META + HEADER_CHAIN_INDEX advancement
/// is **not** done here — the integrator drives the mined header
/// through `ergo_sync::header_proc::process_header` after this returns,
/// then calls `block_proc::process_block` to validate + apply. That
/// keeps the mining path on the same persistence flow as peer-received
/// blocks (PoW verify in `process_header`, validation + state apply in
/// `process_block`).
///
/// Returns the canonical header bytes + header_id the caller hands to
/// `process_header`. The caller's main loop runs roughly:
///
/// ```ignore
/// let (header_bytes, header_id) = apply_mined_block(&mut store, block)?;
/// let _processed_header = header_proc::process_header(&mut store, &header_bytes)?;
/// let _processed_block  = block_proc::process_block(&mut store, &header_id, ...)?;
/// coordinator.on_block_applied(header_id, height);
/// executor.try_apply_next_blocks(...);
/// ```
pub fn apply_mined_block(
    state: &mut StateStore,
    block: SubmittedBlock,
) -> Result<([u8; 32], Vec<u8>), MiningSubmitError> {
    // 1. Authoritative parent-id recheck.
    let live_parent = state.chain_state().best_full_block_id;
    if live_parent != block.parent_id {
        return Err(MiningSubmitError::StaleParent {
            expected: hex::encode(block.parent_id),
            observed: hex::encode(live_parent),
        });
    }

    // 2. Serialize header (caller drives process_header next).
    let (header_bytes, header_id) = serialize_header(&block.header)
        .map_err(|e| MiningSubmitError::SerializeSection(format!("header: {e:?}")))?;
    let header_id_bytes: [u8; 32] = *header_id.as_bytes();

    // 3. Persist BT section.
    let bt = BlockTransactions {
        header_id,
        transactions: block.transactions.clone(),
    };
    let bt_bytes = serialize_bt(&bt, block.header.version)?;
    let bt_id = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        &header_id_bytes,
        block.header.transactions_root.as_bytes(),
    );
    state
        .store_block_section_typed(&bt_id, &bt_bytes, TYPE_BLOCK_TRANSACTIONS)
        .map_err(|e| MiningSubmitError::PersistSection(format!("BT: {e:?}")))?;

    // 4. Persist Extension section.
    let mut ext_fields = Vec::with_capacity(block.extension_fields.len());
    for (k, v) in &block.extension_fields {
        if k.len() != 2 {
            return Err(MiningSubmitError::SerializeSection(format!(
                "extension key must be 2 bytes, got {}",
                k.len()
            )));
        }
        let mut key_arr = [0u8; 2];
        key_arr.copy_from_slice(k);
        ext_fields.push(ExtensionField {
            key: key_arr,
            value: v.clone(),
        });
    }
    let ext = Extension {
        header_id,
        fields: ext_fields,
    };
    let ext_bytes = serialize_extension(&ext)?;
    let ext_id = compute_section_id(
        TYPE_EXTENSION,
        &header_id_bytes,
        block.header.extension_root.as_bytes(),
    );
    state
        .store_block_section_typed(&ext_id, &ext_bytes, TYPE_EXTENSION)
        .map_err(|e| MiningSubmitError::PersistSection(format!("Extension: {e:?}")))?;

    // 5. Persist ADProofs section.
    //    Wire: [32 bytes header_id] [VLQ u32 proof_len] [proof bytes]
    let mut adp_bytes = Vec::with_capacity(32 + 4 + block.ad_proof_bytes.len());
    adp_bytes.extend_from_slice(&header_id_bytes);
    let mut w = VlqWriter::new();
    w.put_u32(block.ad_proof_bytes.len() as u32);
    adp_bytes.extend_from_slice(&w.result());
    adp_bytes.extend_from_slice(&block.ad_proof_bytes);
    let adp_id = compute_section_id(
        TYPE_AD_PROOFS,
        &header_id_bytes,
        block.header.ad_proofs_root.as_bytes(),
    );
    state
        .store_block_section_typed(&adp_id, &adp_bytes, TYPE_AD_PROOFS)
        .map_err(|e| MiningSubmitError::PersistSection(format!("ADProofs: {e:?}")))?;

    Ok((header_id_bytes, header_bytes))
}

fn serialize_bt(bt: &BlockTransactions, block_version: u8) -> Result<Vec<u8>, MiningSubmitError> {
    let mut w = VlqWriter::new();
    write_block_transactions_with_version(&mut w, bt, block_version)
        .map_err(|e| MiningSubmitError::SerializeSection(format!("BT: {e:?}")))?;
    Ok(w.result())
}

fn serialize_extension(ext: &Extension) -> Result<Vec<u8>, MiningSubmitError> {
    let mut w = VlqWriter::new();
    write_extension(&mut w, ext)
        .map_err(|e| MiningSubmitError::SerializeSection(format!("Extension: {e:?}")))?;
    Ok(w.result())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;

    // ----- error paths -----

    #[test]
    fn stale_parent_rejected() {
        // We can't construct a fully-valid SubmittedBlock without going
        // through the orchestrator. This test only exercises the
        // parent-id pre-check failure path by feeding a synthetic
        // mismatched parent_id. Anything past step 1 of
        // apply_mined_block would fail too, but step 1 fails first.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let mut state = StateStore::open(&path).unwrap();
        let mut id = [0u8; 32];
        id[31] = 1;
        let boxes: Vec<([u8; 32], Vec<u8>)> = vec![(id, vec![0xAAu8; 32])];
        state.initialize_genesis(&boxes).unwrap();
        let live = state.chain_state().best_full_block_id;
        // synthesize a SubmittedBlock with parent_id = [0xFF; 32] (won't match)
        let block = synth_block_with_parent([0xFFu8; 32]);
        assert_ne!(live, [0xFFu8; 32]);
        let err = apply_mined_block(&mut state, block).expect_err("must err");
        match err {
            MiningSubmitError::StaleParent { .. } => {}
            other => panic!("expected StaleParent, got {other:?}"),
        }
    }

    fn synth_block_with_parent(parent_id: [u8; 32]) -> SubmittedBlock {
        use ergo_primitives::digest::ADDigest;
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::header::Header;
        use ergo_ser::transaction::Transaction;
        let h = Header {
            version: 3,
            parent_id: Digest32::from_bytes(parent_id).into(),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: 0,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 0,
            height: 1,
            votes: [0u8; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        };
        SubmittedBlock {
            header: h,
            transactions: Vec::<Transaction>::new(),
            extension_fields: Vec::new(),
            ad_proof_bytes: Vec::new(),
            parent_id,
        }
    }
}
