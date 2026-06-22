//! Find the current emission box at the chain tip.
//!
//! At any height H the emission box is `tx[0].output[0]` of the just-
//! applied block at height H. Mining at H+1 consumes that box, so the
//! candidate orchestrator needs an `ErgoBox` value for it.
//!
//! Strategy: walk the parent block's BlockTransactions section, take
//! the first transaction's first output. This avoids a schema change
//! (no need to track emission_box_id in state_meta) and is correct by
//! construction — Scala builds the emission tx as tx[0] for every
//! mainnet block.
//!
//! Cost: one redb read for the parent header (~100 bytes), one for the
//! BlockTransactions section bytes (a few KB to a few hundred KB), one
//! parse. Hot-path acceptable at the candidate refresh cadence (50ms
//! by default).

use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::{read_header, Header};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_state::store::StateError;

use crate::error::MiningError;
use crate::state_view::CandidateStateView;

/// Look up the emission box that would be consumed by the next
/// block. `parent_header_id` is the current best-full-block tip.
///
/// Returns an error if any of:
/// - parent header is not stored
/// - parent BlockTransactions section is not stored
/// - section bytes fail to deserialize
/// - parent block has zero transactions (impossible on mainnet but
///   defensive)
///
/// **Hot-path contract**: this opens two redb read transactions
/// internally (header lookup + section lookup). The caller should
/// invoke once per candidate refresh, not once per /mining/candidate
/// poll.
pub fn lookup_tip_emission_box<V: CandidateStateView>(
    view: &V,
    parent_header_id: &[u8; 32],
) -> Result<ErgoBox, MiningError> {
    let header_bytes = view
        .get_header_bytes(parent_header_id)
        .map_err(state_err)?
        .ok_or_else(|| MiningError::StateRead {
            op: "lookup_tip_emission_box",
            reason: format!(
                "parent header {} not in HEADERS",
                hex::encode(parent_header_id)
            ),
        })?;
    let parent_header = {
        let mut r = VlqReader::new(&header_bytes);
        read_header(&mut r).map_err(|e| MiningError::Decode {
            op: "parent_header",
            reason: format!("{e:?}"),
        })?
    };
    lookup_emission_box_from_parent(view, parent_header_id, &parent_header)
}

/// Same as [`lookup_tip_emission_box`] but takes the already-parsed
/// parent `Header`, saving a read + parse when the caller already has
/// one in hand.
pub fn lookup_emission_box_from_parent<V: CandidateStateView>(
    view: &V,
    parent_header_id: &[u8; 32],
    parent_header: &Header,
) -> Result<ErgoBox, MiningError> {
    let tx_root: [u8; 32] = *parent_header.transactions_root.as_bytes();
    let bt_section_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, parent_header_id, &tx_root);

    let bt_bytes = view
        .block_section(&bt_section_id)
        .map_err(state_err)?
        .ok_or_else(|| MiningError::StateRead {
            op: "lookup_emission_box_from_parent",
            reason: format!(
                "BlockTransactions section {} not stored for parent {}",
                hex::encode(bt_section_id),
                hex::encode(parent_header_id),
            ),
        })?;

    let mut r = VlqReader::new(&bt_bytes);
    let bt = read_block_transactions(&mut r).map_err(|e| MiningError::Decode {
        op: "BlockTransactions",
        reason: format!("{e:?}"),
    })?;
    let emission_tx = bt
        .transactions
        .first()
        .ok_or(MiningError::EmissionInvariant {
            op: "lookup_emission_box_from_parent",
            reason: "parent block has 0 transactions — cannot find emission tx".to_string(),
        })?;
    if emission_tx.output_candidates.is_empty() {
        return Err(MiningError::EmissionInvariant {
            op: "lookup_emission_box_from_parent",
            reason: "emission tx has 0 outputs".into(),
        });
    }

    // tx_id is blake2b256(bytes_to_sign(tx)).
    let bytes_to_sign = ergo_ser::transaction::bytes_to_sign(emission_tx).map_err(|e| {
        MiningError::IdComputation {
            op: "bytes_to_sign",
            reason: format!("{e:?}"),
        }
    })?;
    let tx_id: ModifierId = blake2b256(&bytes_to_sign).into();

    Ok(ErgoBox {
        candidate: emission_tx.output_candidates[0].clone(),
        transaction_id: tx_id,
        index: 0,
    })
}

fn state_err(e: StateError) -> MiningError {
    MiningError::StateRead {
        op: "emission_box_lookup",
        reason: format!("{e:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::header::{serialize_header, Header};
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::transaction::Transaction;
    use ergo_state::store::StateStore;

    fn dummy_pk_tree() -> (Vec<u8>, ergo_ser::ergo_tree::ErgoTree) {
        // Minimal SigmaProp-rooted script: header 0x00 + body `08 d3` =
        // Const(SSigmaProp, TrivialProp::true). A bare Boolean root is rejected at
        // box parse by CheckDeserializedScriptIsSigmaProp (rule 1001).
        let bytes = vec![0x00u8, 0x08, 0xd3];
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        (bytes, tree)
    }

    fn synthetic_emission_tx() -> Transaction {
        let (bytes, tree) = dummy_pk_tree();
        // One input with an arbitrary box_id.
        let input = Input {
            box_id: Digest32::from_bytes([0xAAu8; 32]),
            spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
        };
        // Two outputs: emission (output[0]) + miner (output[1]).
        let em_out = ErgoBoxCandidate::from_trusted_raw_parts(
            73_000_000_000_000u64,
            tree.clone(),
            bytes.clone(),
            1_786_188,
            Vec::new(),
            AdditionalRegisters::empty(),
            vec![0x00],
        );
        let miner_out = ErgoBoxCandidate::from_trusted_raw_parts(
            65_000_000_000,
            tree,
            bytes,
            1_786_188,
            Vec::new(),
            AdditionalRegisters::empty(),
            vec![0x00],
        );
        Transaction {
            inputs: vec![input],
            data_inputs: Vec::new(),
            output_candidates: vec![em_out, miner_out],
        }
    }

    fn synth_header() -> (Header, ModifierId, [u8; 32]) {
        let mut hdr = Header {
            version: 2,
            parent_id: Digest32::from_bytes([0u8; 32]).into(),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: 1_700_000_000_000,
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
        // Synthetic transactions_root: just use the section_digest the
        // reader will expect.
        let tx_root = [0x77u8; 32];
        hdr.transactions_root = Digest32::from_bytes(tx_root);
        let (_bytes, id) = serialize_header(&hdr).unwrap();
        (hdr, id, tx_root)
    }

    // ----- happy path -----

    #[test]
    fn discovers_emission_box_from_block_transactions_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let store = StateStore::open(&path).unwrap();

        let (hdr, hdr_id, tx_root) = synth_header();
        let hdr_id_bytes: [u8; 32] = *hdr_id.as_bytes();
        let (hdr_bytes, _) = serialize_header(&hdr).unwrap();
        store.store_header(&hdr_id_bytes, &hdr_bytes).unwrap();

        // Build the BlockTransactions section bytes and write under
        // compute_section_id(102, header_id, transactions_root).
        let bt = BlockTransactions {
            header_id: hdr_id,
            transactions: vec![synthetic_emission_tx()],
        };
        let mut w = VlqWriter::new();
        write_block_transactions_with_version(&mut w, &bt, 2).unwrap();
        let bt_bytes = w.result();
        let section_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &hdr_id_bytes, &tx_root);
        store.store_block_section(&section_id, &bt_bytes).unwrap();

        let em = lookup_tip_emission_box(&store, &hdr_id_bytes).expect("lookup");
        assert_eq!(em.index, 0);
        assert_eq!(em.candidate.value, 73_000_000_000_000);
    }

    // ----- error paths -----

    #[test]
    fn missing_header_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let store = StateStore::open(&path).unwrap();
        let err = lookup_tip_emission_box(&store, &[0u8; 32]).expect_err("must error");
        let msg = format!("{err:?}");
        assert!(msg.contains("parent header"), "{msg}");
    }
}
