//! Tests for `StateStore::tx_diff_since` — linear apply, reorg, errors.
//!
//! Builds a synthetic chain directly by stamping `header_meta`, headers,
//! and block_sections under the hood. This exercises the walk + load
//! path without requiring a real genesis or UTXO state.

use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::{GroupElement, GROUP_ELEMENT_LENGTH};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::{read_ergo_tree, ErgoTree};
use ergo_ser::header::{write_header, Header};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::{bytes_to_sign, Transaction};
use ergo_state::chain::HeaderMeta;
use ergo_state::diff::{TipPointer, TxDiffError};
use ergo_state::store::StateStore;
use tempfile::TempDir;

// ---- Helpers: minimal synthetic block plumbing ------------------

fn ge_zero() -> GroupElement {
    GroupElement::from_bytes([0u8; GROUP_ELEMENT_LENGTH])
}

fn minimal_ergo_tree() -> ErgoTree {
    // v0 header, body = `08 d3` (Const(SSigmaProp, TrivialProp::true)). A bare
    // Boolean root is rejected at box parse by CheckDeserializedScriptIsSigmaProp.
    let bytes = vec![0x00u8, 0x08, 0xd3];
    let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
    read_ergo_tree(&mut r).unwrap()
}

fn minimal_candidate(value: u64) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        minimal_ergo_tree(),
        0,
        Vec::new(),
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn minimal_tx(input_box_ids: &[[u8; 32]]) -> Transaction {
    let inputs = input_box_ids
        .iter()
        .map(|id| Input {
            box_id: Digest32::from_bytes(*id),
            spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
        })
        .collect();
    Transaction {
        inputs,
        data_inputs: Vec::new(),
        output_candidates: vec![minimal_candidate(1_000)],
    }
}

fn synthetic_header(parent_id: [u8; 32], height: u32, transactions_root: Digest32) -> Header {
    Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent_id),
        ad_proofs_root: Digest32::ZERO,
        transactions_root,
        state_root: ADDigest::from_bytes([0u8; 33]),
        timestamp: 1_000_000 + height as u64,
        extension_root: Digest32::ZERO,
        n_bits: 0,
        height,
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: ge_zero(),
            nonce: [0u8; 8],
        },
    }
}

fn synthetic_header_bytes(h: &Header) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_header(&mut w, h).expect("synthetic header fits wire bounds");
    w.result()
}

fn synthetic_bt_bytes(header_id: [u8; 32], txs: &[Transaction]) -> Vec<u8> {
    let bt = BlockTransactions {
        header_id: ModifierId::from_bytes(header_id),
        transactions: txs.to_vec(),
    };
    let mut w = VlqWriter::new();
    write_block_transactions(&mut w, &bt).unwrap();
    w.result()
}

fn section_id_for(header_id: &[u8; 32], tx_root: &Digest32) -> [u8; 32] {
    compute_section_id(TYPE_BLOCK_TRANSACTIONS, header_id, tx_root.as_bytes())
}

/// Compute the Merkle-less "transactions root" we store — since the
/// diff code uses the root only to address the section, any stable
/// function is fine. Here we hash the concatenation of tx ids.
fn transactions_root(txs: &[Transaction]) -> Digest32 {
    let mut buf = Vec::new();
    for tx in txs {
        let msg = bytes_to_sign(tx).unwrap();
        buf.extend_from_slice(blake2b256(&msg).as_bytes());
    }
    blake2b256(&buf)
}

struct SyntheticBlock {
    height: u32,
    parent_id: [u8; 32],
    header: Header,
    header_bytes: Vec<u8>,
    header_id: [u8; 32],
    section_id: [u8; 32],
    section_bytes: Vec<u8>,
    txs: Vec<Transaction>,
}

fn build_block(height: u32, parent_id: [u8; 32], input_box_seed: u8) -> SyntheticBlock {
    // One tx per block, spending a distinct synthetic box so tx_id and
    // spent_inputs are unique across blocks.
    let txs = vec![minimal_tx(&[[input_box_seed; 32]])];
    let root = transactions_root(&txs);
    let header = synthetic_header(parent_id, height, root);
    let header_bytes = synthetic_header_bytes(&header);
    let header_id = *blake2b256(&header_bytes).as_bytes();
    let section_bytes = synthetic_bt_bytes(header_id, &txs);
    let section_id = section_id_for(&header_id, &root);
    SyntheticBlock {
        height,
        parent_id,
        header,
        header_bytes,
        header_id,
        section_id,
        section_bytes,
        txs,
    }
}

fn open_store() -> (TempDir, StateStore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let store = StateStore::open(&path).unwrap();
    (dir, store)
}

fn seed_block(store: &StateStore, block: &SyntheticBlock, parent_score: &[u8]) {
    store
        .store_header(&block.header_id, &block.header_bytes)
        .unwrap();
    store
        .store_block_section(&block.section_id, &block.section_bytes)
        .unwrap();
    let meta = HeaderMeta {
        parent_id: block.parent_id,
        height: block.height,
        cumulative_score: parent_score.to_vec(),
        pow_validity: 1,
        timestamp: block.header.timestamp,
    };
    store.store_header_meta(&block.header_id, &meta).unwrap();
}

/// Chain from genesis to `tip` via linear parent links.
fn build_linear_chain(n: u32) -> Vec<SyntheticBlock> {
    let mut parent = [0u8; 32];
    let mut out = Vec::with_capacity(n as usize);
    for h in 1..=n {
        let blk = build_block(h, parent, h as u8);
        parent = blk.header_id;
        out.push(blk);
    }
    out
}

// ---- Tests ------------------------------------------------------

// ----- happy path -----

#[test]
fn empty_diff_when_since_equals_tip() {
    let (_dir, mut store) = open_store();
    let chain = build_linear_chain(3);
    for blk in &chain {
        seed_block(&store, blk, &[0]);
    }
    let tip = chain.last().unwrap();
    store
        .test_force_set_best_full_block_unsafe(tip.header_id, tip.height)
        .unwrap();

    let diff = store
        .tx_diff_since(TipPointer {
            height: tip.height,
            header_id: tip.header_id,
        })
        .unwrap();
    assert!(diff.applied.is_empty());
    assert!(diff.demoted.is_empty());
    assert!(diff.applied_spent_inputs.is_empty());
    assert_eq!(diff.new_tip.header_id, tip.header_id);
}

#[test]
fn linear_apply_returns_applied_chain_forward() {
    let (_dir, mut store) = open_store();
    let chain = build_linear_chain(3);
    for blk in &chain {
        seed_block(&store, blk, &[0]);
    }
    let since = &chain[0];
    let tip = chain.last().unwrap();
    store
        .test_force_set_best_full_block_unsafe(tip.header_id, tip.height)
        .unwrap();

    let diff = store
        .tx_diff_since(TipPointer {
            height: since.height,
            header_id: since.header_id,
        })
        .unwrap();
    assert_eq!(diff.applied.len(), 2, "blocks 2 and 3 applied");
    assert!(diff.demoted.is_empty());
    // Order: block 2 tx, then block 3 tx.
    let expected_b2_id = *blake2b256(&bytes_to_sign(&chain[1].txs[0]).unwrap()).as_bytes();
    let expected_b3_id = *blake2b256(&bytes_to_sign(&chain[2].txs[0]).unwrap()).as_bytes();
    assert_eq!(diff.applied[0].tx_id, expected_b2_id);
    assert_eq!(diff.applied[1].tx_id, expected_b3_id);
    // applied_spent_inputs = union of all applied tx inputs.
    assert!(diff.applied_spent_inputs.contains(&[2u8; 32]));
    assert!(diff.applied_spent_inputs.contains(&[3u8; 32]));
}

#[test]
fn too_far_behind_when_since_header_missing() {
    let (_dir, mut store) = open_store();
    let chain = build_linear_chain(2);
    for blk in &chain {
        seed_block(&store, blk, &[0]);
    }
    let tip = chain.last().unwrap();
    store
        .test_force_set_best_full_block_unsafe(tip.header_id, tip.height)
        .unwrap();

    let err = store
        .tx_diff_since(TipPointer {
            height: 1,
            header_id: [0x99; 32], // unseen
        })
        .unwrap_err();
    assert_eq!(err, TxDiffError::TooFarBehind);
}

#[test]
fn missing_block_section_reports_cleanly() {
    let (_dir, mut store) = open_store();
    let chain = build_linear_chain(2);
    for blk in &chain {
        seed_block(&store, blk, &[0]);
    }
    let tip = chain.last().unwrap();
    // Clobber the tip's section bytes with nonsense so parsing fails.
    store
        .store_block_section(&tip.section_id, &[0xFF; 4])
        .unwrap();
    store
        .test_force_set_best_full_block_unsafe(tip.header_id, tip.height)
        .unwrap();

    let err = store
        .tx_diff_since(TipPointer {
            height: chain[0].height,
            header_id: chain[0].header_id,
        })
        .unwrap_err();
    match err {
        TxDiffError::MissingSections { height, header_id } => {
            assert_eq!(height, tip.height);
            assert_eq!(header_id, tip.header_id);
        }
        other => panic!("expected MissingSections, got {other:?}"),
    }
}

#[test]
fn reorg_produces_demoted_and_applied_streams() {
    // Chain shape:
    //   genesis → A1 → A2      (old "since" chain)
    //          ↘ B1 → B2 → B3  (new chain, now tip)
    //
    // LCA is genesis. `since` = A2, tip = B3.
    let (_dir, mut store) = open_store();

    let a1 = build_block(1, [0u8; 32], 10);
    let a2 = build_block(2, a1.header_id, 11);
    let b1 = build_block(1, [0u8; 32], 20);
    let b2 = build_block(2, b1.header_id, 21);
    let b3 = build_block(3, b2.header_id, 22);
    for blk in [&a1, &a2, &b1, &b2, &b3] {
        seed_block(&store, blk, &[0]);
    }
    store
        .test_force_set_best_full_block_unsafe(b3.header_id, b3.height)
        .unwrap();

    let diff = store
        .tx_diff_since(TipPointer {
            height: a2.height,
            header_id: a2.header_id,
        })
        .unwrap();

    // Demoted: old chain A2 → A1, reversed to chain-forward A1, A2.
    // But both are children of the genesis common point, so demoted
    // starts at height 1 (A1) and ends at height 2 (A2).
    assert_eq!(diff.demoted.len(), 2, "demoted covers A1 + A2 txs");
    let expected_a1 = *blake2b256(&bytes_to_sign(&a1.txs[0]).unwrap()).as_bytes();
    let expected_a2 = *blake2b256(&bytes_to_sign(&a2.txs[0]).unwrap()).as_bytes();
    assert_eq!(diff.demoted[0].tx_id, expected_a1);
    assert_eq!(diff.demoted[1].tx_id, expected_a2);
    // Demoted bytes preserved for relay.
    assert!(!diff.demoted[0].bytes.is_empty());

    // Applied: new chain B1, B2, B3.
    assert_eq!(diff.applied.len(), 3);
    let expected_b1 = *blake2b256(&bytes_to_sign(&b1.txs[0]).unwrap()).as_bytes();
    let expected_b3 = *blake2b256(&bytes_to_sign(&b3.txs[0]).unwrap()).as_bytes();
    assert_eq!(diff.applied[0].tx_id, expected_b1);
    assert_eq!(diff.applied[2].tx_id, expected_b3);

    // applied_spent_inputs is the union of B1/B2/B3 inputs.
    assert!(diff.applied_spent_inputs.contains(&[20u8; 32]));
    assert!(diff.applied_spent_inputs.contains(&[21u8; 32]));
    assert!(diff.applied_spent_inputs.contains(&[22u8; 32]));
    // Old-chain inputs NOT in applied_spent_inputs — their boxes aren't
    // committed, even though A1/A2 spent them.
    assert!(!diff.applied_spent_inputs.contains(&[10u8; 32]));
}

#[test]
fn committed_tip_reflects_chain_state() {
    let (_dir, mut store) = open_store();
    let chain = build_linear_chain(2);
    for blk in &chain {
        seed_block(&store, blk, &[0]);
    }
    let tip = chain.last().unwrap();
    store
        .test_force_set_best_full_block_unsafe(tip.header_id, tip.height)
        .unwrap();
    let got = store.committed_tip();
    assert_eq!(got.height, tip.height);
    assert_eq!(got.header_id, tip.header_id);
}

#[test]
fn since_height_mismatch_is_too_far_behind() {
    // If the caller's retained `since` height disagrees with what
    // `header_meta` says, we bail cleanly rather than produce a diff
    // relative to some other branch.
    let (_dir, mut store) = open_store();
    let chain = build_linear_chain(2);
    for blk in &chain {
        seed_block(&store, blk, &[0]);
    }
    store
        .test_force_set_best_full_block_unsafe(
            chain.last().unwrap().header_id,
            chain.last().unwrap().height,
        )
        .unwrap();

    let err = store
        .tx_diff_since(TipPointer {
            height: 99, // wrong
            header_id: chain[0].header_id,
        })
        .unwrap_err();
    assert_eq!(err, TxDiffError::TooFarBehind);
}
