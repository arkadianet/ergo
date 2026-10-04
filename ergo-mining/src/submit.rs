//! Block-application path for accepted mining solutions.
//!
//! v12 §6 step 6 — the executor-side gate. Runs **inside the action
//! loop** so reads of `chain_state` are serialized with applies, closing
//! the TOCTOU window the HTTP-side step-4 check can't.
//!
//! Wire-up at the node level: hold a
//! `mpsc::Sender<MiningSubmitRequest>` on the API task side, drain it
//! once per tick in the main loop just like `submit_rx` for
//! `SubmitRequest`, and inside the drain arm call
//! [`prepare_mined_block`], run the header pipeline on its header, then
//! call [`store_mined_sections`].

use ergo_primitives::writer::VlqWriter;
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::extension::{write_extension, Extension, ExtensionField};
use ergo_ser::header::serialize_header;
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::store::{StateError, StateStore};
use thiserror::Error;
use tokio::sync::oneshot;

use crate::solution::SubmittedBlock;

/// Request shipped from the API task to the main loop. The main loop
/// drains it, stores the block through [`prepare_mined_block`], the header
/// pipeline and [`store_mined_sections`], and replies through `reply`.
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
    /// Section persistence failed: the store refused or could not commit
    /// the write.
    #[error("persist section: {0}")]
    PersistSection(#[source] StateError),
    /// Block validation or apply failed downstream.
    #[error("apply block: {0}")]
    Apply(String),
}

/// An accepted mining solution in its stored form: the canonical header
/// the caller drives through the header pipeline, and the three sections
/// [`store_mined_sections`] writes once that header is stored.
#[derive(Debug)]
pub struct MinedBlock {
    /// `blake2b256` of [`MinedBlock::header_bytes`].
    pub header_id: [u8; 32],
    /// Canonical header bytes.
    pub header_bytes: Vec<u8>,
    /// The block's height: the applied tip's plus one.
    pub height: u32,
    sections: [MinedSection; 3],
}

/// One serialized section under its canonical modifier id.
#[derive(Debug)]
struct MinedSection {
    id: [u8; 32],
    type_id: u8,
    bytes: Vec<u8>,
}

impl MinedBlock {
    /// Whether every section of the block is in `state`. When a resubmitted
    /// solution's header is already stored, missing sections are what a
    /// failed [`store_mined_sections`] leaves, and the caller writes them.
    /// Reads without draining persistence results, so a pending persistence
    /// failure still reaches the apply that follows.
    pub fn sections_stored(&self, state: &StateStore) -> Result<bool, StateError> {
        for section in &self.sections {
            if state.read_section_for_serving(&section.id, 1)?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Recheck an accepted solution's parent and serialize the block, writing
/// nothing. The parent recheck (v12 §6 step 6) is the consensus-bearing
/// TOCTOU close: the block must still extend the applied tip.
///
/// The caller then drives [`MinedBlock::header_bytes`] through
/// `ergo_sync::header_proc` (PoW re-verify, chain linkage, difficulty,
/// persistence into HEADERS + HEADER_META + SECTION_HEIGHT_INDEX) and only
/// after it is stored calls [`store_mined_sections`], then validates and
/// applies the block through the executor. Header before sections is the
/// order every block reaches this store in: peers only deliver sections
/// of known headers, and Scala's `CandidateGenerator.sendToNodeView` hands
/// the header to its view holder before the sections.
///
/// ```ignore
/// let mined = prepare_mined_block(&store, block)?;
/// let processed = header_proc::process_header_cfg_with_genesis(&mut store, &mined.header_bytes, ..)?;
/// store_mined_sections(&store, &mined)?;
/// // A resubmission whose header is known stores the sections only when
/// // `mined.sections_stored(&store)?` is false.
/// executor.execute(Action::AssembleBlock { header_id: mined.header_id }, ..);
/// ```
pub fn prepare_mined_block(
    state: &StateStore,
    block: SubmittedBlock,
) -> Result<MinedBlock, MiningSubmitError> {
    // 1. Authoritative parent-id recheck.
    let live_parent = state.chain_state().best_full_block_id;
    if live_parent != block.parent_id {
        return Err(MiningSubmitError::StaleParent {
            expected: hex::encode(block.parent_id),
            observed: hex::encode(live_parent),
        });
    }

    // 2. Serialize the header.
    let (header_bytes, header_id) = serialize_header(&block.header)
        .map_err(|e| MiningSubmitError::SerializeSection(format!("header: {e:?}")))?;
    let header_id_bytes: [u8; 32] = *header_id.as_bytes();

    // 3. BlockTransactions.
    let bt = BlockTransactions {
        header_id,
        transactions: block.transactions,
    };
    let bt_bytes = serialize_bt(&bt, block.header.version)?;
    let bt_id = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        &header_id_bytes,
        block.header.transactions_root.as_bytes(),
    );

    // 4. Extension.
    let mut ext_fields = Vec::with_capacity(block.extension_fields.len());
    for (k, v) in block.extension_fields {
        let key: [u8; 2] = k.as_slice().try_into().map_err(|_| {
            MiningSubmitError::SerializeSection(format!(
                "extension key must be 2 bytes, got {}",
                k.len()
            ))
        })?;
        ext_fields.push(ExtensionField { key, value: v });
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

    // 5. ADProofs.
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

    Ok(MinedBlock {
        header_id: header_id_bytes,
        header_bytes,
        height: block.header.height,
        sections: [
            MinedSection {
                id: bt_id,
                type_id: TYPE_BLOCK_TRANSACTIONS,
                bytes: bt_bytes,
            },
            MinedSection {
                id: ext_id,
                type_id: TYPE_EXTENSION,
                bytes: ext_bytes,
            },
            MinedSection {
                id: adp_id,
                type_id: TYPE_AD_PROOFS,
                bytes: adp_bytes,
            },
        ],
    })
}

/// Persist the three sections of a [`MinedBlock`] under their canonical
/// modifier ids and type bytes (BlockTransactions, Extension, ADProofs) in
/// one durable transaction: all three are on disk when this returns `Ok`,
/// and none is written when it returns `Err`.
///
/// Call only once the header pipeline has stored the block's header. The
/// store's prune guard admits a section only when the header's
/// SECTION_HEIGHT_INDEX row puts it at or above the minimal full-block
/// height, so on a store whose serving window starts above height one
/// (pruned, or bootstrapped from a UTXO snapshot or NiPoPoW proof) a
/// section written before its header is refused. No peer holds these
/// sections until this node serves them, so they are committed durably
/// before the block is announced or applied: a node killed in between
/// would otherwise restart with the header, possibly as its best header,
/// and no body for it anywhere.
pub fn store_mined_sections(
    state: &StateStore,
    mined: &MinedBlock,
) -> Result<(), MiningSubmitError> {
    let sections = mined
        .sections
        .each_ref()
        .map(|section| (&section.id, section.bytes.as_slice(), section.type_id));
    state
        .store_block_sections_durable(&sections)
        .map_err(MiningSubmitError::PersistSection)
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
        // mismatched parent_id.
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
        let err = prepare_mined_block(&state, block).expect_err("must err");
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
