//! Integration tests for `rollback_one_block`.
//!
//! Builds synthetic blocks via `apply_block`, then asserts that
//! `rollback_one_block` reverts the indexer to the exact pre-apply
//! state — meta, NUMERIC_*, IndexedErgoBox, IndexedErgoTransaction,
//! and the undo entry.

use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::input::{ContextExtension, DataInput, Input, SpendingProof};
use ergo_ser::opcode::{Body, Expr};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use ergo_ser::transaction::{transaction_id, Transaction};
use tempfile::TempDir;

use ergo_indexer::{
    apply_block, rollback_one_block, IndexerBlock, IndexerError, IndexerMeta, IndexerStore,
};

fn size_delimited_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        } as Body,
    }
}

fn candidate(value: u64, height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        size_delimited_tree(),
        height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn candidate_with_tokens(value: u64, height: u32, tokens: Vec<Token>) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        size_delimited_tree(),
        height,
        tokens,
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn tree_hash_of(tree: &ErgoTree) -> Digest32 {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, tree).unwrap();
    ergo_primitives::digest::blake2b256(&w.result())
}

fn fake_input(box_id_seed: u8) -> Input {
    Input {
        box_id: Digest32::from_bytes([box_id_seed; 32]),
        spending_proof: SpendingProof::new(vec![0xAB, 0xCD, 0xEF], ContextExtension::empty())
            .unwrap(),
    }
}

fn open_store() -> (IndexerStore, TempDir) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();
    (store, tmp)
}

fn sealed_box_id(tx: &Transaction, output_idx: u16) -> Digest32 {
    let tx_id = transaction_id(tx).unwrap();
    let sealed = ErgoBox {
        candidate: tx.output_candidates[output_idx as usize].clone(),
        transaction_id: tx_id,
        index: output_idx,
    };
    sealed.box_id().unwrap()
}

// ----- happy path -----

#[test]
fn rollback_genesis_block_clears_state_to_empty() {
    let (store, _tmp) = open_store();

    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_000_000, 1)],
    };
    let header_id = Digest32::from_bytes([0x11; 32]);
    let block = IndexerBlock {
        height: 1,
        header_id,
        transactions: std::slice::from_ref(&tx),
    };

    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
    let meta_back = rollback_one_block(&store, &meta1, &block).unwrap();

    assert_eq!(meta_back, IndexerMeta::empty());
    assert_eq!(store.read_meta().unwrap(), IndexerMeta::empty());

    // Per-row state cleared.
    let out0 = sealed_box_id(&tx, 0);
    let out1 = sealed_box_id(&tx, 1);
    assert!(store.read_box(&out0).unwrap().is_none());
    assert!(store.read_box(&out1).unwrap().is_none());
    assert!(store.read_numeric_box(0).unwrap().is_none());
    assert!(store.read_numeric_box(1).unwrap().is_none());

    let tx_id = transaction_id(&tx).unwrap();
    assert!(store.read_tx(tx_id.as_digest()).unwrap().is_none());
    assert!(store.read_numeric_tx(0).unwrap().is_none());

    // Undo entry cleaned up.
    assert!(store.read_undo(1).unwrap().is_none());
}

#[test]
fn rollback_child_block_restores_post_genesis_state_byte_for_byte() {
    let (store, _tmp) = open_store();

    // Block 1: genesis-ish, two outputs.
    let tx_a = Transaction {
        inputs: vec![fake_input(0xFF)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_000_000, 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    // Snapshot post-genesis state.
    let out0_id = sealed_box_id(&tx_a, 0);
    let out1_id = sealed_box_id(&tx_a, 1);
    let snap_box0 = store.read_box(&out0_id).unwrap().unwrap();
    let snap_box1 = store.read_box(&out1_id).unwrap().unwrap();
    let snap_meta = store.read_meta().unwrap();
    let tx_a_id = transaction_id(&tx_a).unwrap();
    let snap_tx_a = store.read_tx(tx_a_id.as_digest()).unwrap().unwrap();

    // Block 2: spends output 0, creates output 2.
    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: out0_id,
            spending_proof: SpendingProof::new(
                vec![0xCA, 0xFE, 0xBA, 0xBE],
                ContextExtension::empty(),
            )
            .unwrap(),
        }],
        data_inputs: vec![DataInput {
            box_id: Digest32::from_bytes([0x55; 32]),
        }],
        output_candidates: vec![candidate(900_000, 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    let meta2 = apply_block(&store, &meta1, &block2).unwrap();

    // Roll back block 2.
    let meta_back = rollback_one_block(&store, &meta2, &block2).unwrap();

    // Meta returned and persisted is byte-equal to post-genesis snapshot.
    assert_eq!(meta_back, snap_meta);
    assert_eq!(store.read_meta().unwrap(), snap_meta);

    // Spent input restored: spending_* fields cleared, global_index unchanged.
    let restored0 = store.read_box(&out0_id).unwrap().unwrap();
    assert_eq!(restored0, snap_box0);
    assert!(!restored0.is_spent());
    assert_eq!(restored0.global_index, 0);

    // Other genesis output untouched.
    let restored1 = store.read_box(&out1_id).unwrap().unwrap();
    assert_eq!(restored1, snap_box1);

    // Block-2 output is gone.
    let out2_id = sealed_box_id(&tx_b, 0);
    assert!(store.read_box(&out2_id).unwrap().is_none());
    assert!(store.read_numeric_box(2).unwrap().is_none());

    // NUMERIC_BOX[0..2] preserved.
    assert_eq!(store.read_numeric_box(0).unwrap(), Some(out0_id));
    assert_eq!(store.read_numeric_box(1).unwrap(), Some(out1_id));

    // Block-2 tx record is gone, NUMERIC_TX[1] is gone, NUMERIC_TX[0] preserved.
    let tx_b_id = transaction_id(&tx_b).unwrap();
    assert!(store.read_tx(tx_b_id.as_digest()).unwrap().is_none());
    assert!(store.read_numeric_tx(1).unwrap().is_none());
    assert_eq!(
        store.read_numeric_tx(0).unwrap(),
        Some(*tx_a_id.as_digest())
    );

    // Block-1 tx record byte-equal to pre-rollback snapshot.
    assert_eq!(
        store.read_tx(tx_a_id.as_digest()).unwrap().unwrap(),
        snap_tx_a
    );

    // Undo entry for height 2 removed; undo[1] still there.
    assert!(store.read_undo(2).unwrap().is_none());
    assert!(store.read_undo(1).unwrap().is_some());
}

#[test]
fn rollback_two_tx_block_walks_in_reverse_and_clears_all_counters() {
    let (store, _tmp) = open_store();

    let tx0 = Transaction {
        inputs: vec![fake_input(0xA0)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000, 1), candidate(2_000, 1)],
    };
    let tx1 = Transaction {
        inputs: vec![fake_input(0xA1)],
        data_inputs: vec![],
        output_candidates: vec![candidate(3_000, 1)],
    };
    let txs = vec![tx0.clone(), tx1.clone()];
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0xBB; 32]),
        transactions: &txs,
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
    assert_eq!(meta1.global_tx_index, 2);
    assert_eq!(meta1.global_box_index, 3);

    let meta_back = rollback_one_block(&store, &meta1, &block).unwrap();

    assert_eq!(meta_back, IndexerMeta::empty());
    assert_eq!(store.read_meta().unwrap(), IndexerMeta::empty());

    let tx0_id = transaction_id(&tx0).unwrap();
    let tx1_id = transaction_id(&tx1).unwrap();
    assert!(store.read_tx(tx0_id.as_digest()).unwrap().is_none());
    assert!(store.read_tx(tx1_id.as_digest()).unwrap().is_none());
    for n in 0..3u64 {
        assert!(store.read_numeric_box(n).unwrap().is_none());
    }
    for n in 0..2u64 {
        assert!(store.read_numeric_tx(n).unwrap().is_none());
    }
    for idx in 0..2u16 {
        assert!(store.read_box(&sealed_box_id(&tx0, idx)).unwrap().is_none());
    }
    assert!(store.read_box(&sealed_box_id(&tx1, 0)).unwrap().is_none());
    assert!(store.read_undo(1).unwrap().is_none());
}

#[test]
fn rollback_at_empty_meta_errors_without_touching_db() {
    let (store, _tmp) = open_store();
    let meta0 = IndexerMeta::empty();
    assert_eq!(store.read_meta().unwrap(), meta0);

    let stub_tx = Transaction {
        inputs: vec![fake_input(0x01)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1, 1)],
    };
    let block = IndexerBlock {
        height: 0,
        header_id: Digest32::from_bytes([0x00; 32]),
        transactions: std::slice::from_ref(&stub_tx),
    };
    let err = rollback_one_block(&store, &meta0, &block).unwrap_err();
    assert!(
        matches!(err, IndexerError::NothingToRollback { .. }),
        "got {err:?}"
    );
    assert_eq!(store.read_meta().unwrap(), meta0);
}

#[test]
fn rollback_with_height_mismatch_errors_without_mutating_state() {
    let (store, _tmp) = open_store();

    // Apply block at height 1.
    let tx = Transaction {
        inputs: vec![fake_input(0xC0)],
        data_inputs: vec![],
        output_candidates: vec![candidate(100, 1)],
    };
    let header_id = Digest32::from_bytes([0xCC; 32]);
    let block = IndexerBlock {
        height: 1,
        header_id,
        transactions: std::slice::from_ref(&tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
    let snap = store.read_meta().unwrap();

    // Now ask to roll back a block claiming height 7.
    let bad_block = IndexerBlock {
        height: 7,
        header_id,
        transactions: std::slice::from_ref(&tx),
    };
    let err = rollback_one_block(&store, &meta1, &bad_block).unwrap_err();
    assert!(
        matches!(err, IndexerError::HeightMismatch { .. }),
        "got {err:?}"
    );

    // No mutations.
    assert_eq!(store.read_meta().unwrap(), snap);
    assert!(store.read_undo(1).unwrap().is_some());
    let out0 = sealed_box_id(&tx, 0);
    assert!(store.read_box(&out0).unwrap().is_some());
}

#[test]
fn rollback_with_header_mismatch_errors_without_mutating_state() {
    let (store, _tmp) = open_store();

    let tx = Transaction {
        inputs: vec![fake_input(0xD0)],
        data_inputs: vec![],
        output_candidates: vec![candidate(200, 1)],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0xD1; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
    let snap = store.read_meta().unwrap();

    let bad_block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0xEE; 32]), // wrong
        transactions: std::slice::from_ref(&tx),
    };
    let err = rollback_one_block(&store, &meta1, &bad_block).unwrap_err();
    assert!(
        matches!(err, IndexerError::HeaderMismatch { .. }),
        "got {err:?}"
    );

    assert_eq!(store.read_meta().unwrap(), snap);
    assert!(store.read_undo(1).unwrap().is_some());
}

#[test]
fn rollback_when_undo_entry_is_missing_returns_undo_missing() {
    let (store, _tmp) = open_store();

    // Construct synthetic state: meta says height 5 indexed, but no
    // undo[5] (commit_rollback_meta_only writes the meta and removes
    // the undo entry at the given height — for a fresh DB with no
    // undo[5], the remove is a no-op and we end up with a meta that
    // points at a height with no matching undo).
    let header_id = Digest32::from_bytes([0xCA; 32]);
    let synth_meta = IndexerMeta {
        indexed_height: 5,
        indexed_header_id: Some(header_id),
        global_tx_index: 100,
        global_box_index: 200,
    };
    store.commit_rollback_meta_only(&synth_meta, 5).unwrap();
    assert_eq!(store.read_meta().unwrap(), synth_meta);
    assert!(store.read_undo(5).unwrap().is_none());

    // Stub block — body is never inspected because the undo check runs
    // first.
    let stub_tx = Transaction {
        inputs: vec![fake_input(0xFE)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1, 5)],
    };
    let block = IndexerBlock {
        height: 5,
        header_id,
        transactions: std::slice::from_ref(&stub_tx),
    };

    let err = rollback_one_block(&store, &synth_meta, &block).unwrap_err();
    assert!(
        matches!(err, IndexerError::UndoMissing(5)),
        "expected UndoMissing(5), got {err:?}"
    );

    // Atomicity: meta unchanged.
    assert_eq!(store.read_meta().unwrap(), synth_meta);
}

#[test]
fn apply_then_rollback_then_reapply_yields_identical_state() {
    let (store, _tmp) = open_store();

    let tx_a = Transaction {
        inputs: vec![fake_input(0x01)],
        data_inputs: vec![],
        output_candidates: vec![candidate(500, 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x10; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: sealed_box_id(&tx_a, 0),
            spending_proof: SpendingProof::new(vec![0x99], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(400, 2), candidate(50, 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x20; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };

    // First apply of block 2.
    let meta2_a = apply_block(&store, &meta1, &block2).unwrap();
    let snap_box0 = store.read_box(&sealed_box_id(&tx_a, 0)).unwrap().unwrap();
    let snap_box1 = store.read_box(&sealed_box_id(&tx_b, 0)).unwrap().unwrap();
    let snap_box2 = store.read_box(&sealed_box_id(&tx_b, 1)).unwrap().unwrap();
    let snap_tx_b = store
        .read_tx(transaction_id(&tx_b).unwrap().as_digest())
        .unwrap()
        .unwrap();
    let snap_undo2 = store.read_undo(2).unwrap().unwrap();

    // Roll back, then re-apply same block 2.
    let meta_back = rollback_one_block(&store, &meta2_a, &block2).unwrap();
    assert_eq!(meta_back, meta1);
    let meta2_b = apply_block(&store, &meta1, &block2).unwrap();

    // Re-applied state must match the original apply byte-for-byte.
    assert_eq!(meta2_b, meta2_a);
    assert_eq!(
        store.read_box(&sealed_box_id(&tx_a, 0)).unwrap().unwrap(),
        snap_box0
    );
    assert_eq!(
        store.read_box(&sealed_box_id(&tx_b, 0)).unwrap().unwrap(),
        snap_box1
    );
    assert_eq!(
        store.read_box(&sealed_box_id(&tx_b, 1)).unwrap().unwrap(),
        snap_box2
    );
    assert_eq!(
        store
            .read_tx(transaction_id(&tx_b).unwrap().as_digest())
            .unwrap()
            .unwrap(),
        snap_tx_b
    );
    assert_eq!(store.read_undo(2).unwrap().unwrap(), snap_undo2);
}

// -- BalanceInfo apply + rollback inverse ------------------------------------

#[test]
fn rollback_returns_owner_balance_to_pre_block_snapshot() {
    // Block 1 leaves the owner address at 3.5M; block 2 spends 1M and
    // creates 0.9M (net 3.4M). Rolling block 2 back must restore 3.5M
    // exactly — both `subtract_box` (output reverse) and `add_box`
    // (input reverse) cancel block 2's deltas.
    let (store, _tmp) = open_store();

    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_500_000, 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    let snap_addr = store.read_address(&th).unwrap().unwrap();
    assert_eq!(snap_addr.balance.as_ref().unwrap().nano_ergs, 3_500_000);

    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: sealed_box_id(&tx_a, 0), // 1M output
            spending_proof: SpendingProof::new(vec![0x01], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(900_000, 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    let meta2 = apply_block(&store, &meta1, &block2).unwrap();
    assert_eq!(
        store
            .read_address(&th)
            .unwrap()
            .unwrap()
            .balance
            .unwrap()
            .nano_ergs,
        3_400_000,
    );

    rollback_one_block(&store, &meta2, &block2).unwrap();
    assert_eq!(store.read_address(&th).unwrap().unwrap(), snap_addr);
}

#[test]
fn rollback_genesis_zeroes_owner_balance_but_address_record_remains() {
    // Genesis creates a brand-new address record with 3.5M balance.
    // Rollback runs `subtract_box` against that record — Scala's
    // BalanceInfo.subtract clamps nano_ergs at 0 and drops zero-tokens,
    // and we never delete the row (matches Scala's upsert-only model).
    // So post-rollback the record exists with an empty balance.
    let (store, _tmp) = open_store();

    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_500_000, 1)],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
    let th = tree_hash_of(&size_delimited_tree());
    assert_eq!(
        store
            .read_address(&th)
            .unwrap()
            .unwrap()
            .balance
            .unwrap()
            .nano_ergs,
        3_500_000,
    );

    rollback_one_block(&store, &meta1, &block).unwrap();
    let after = store.read_address(&th).unwrap().expect("record stays");
    let bal = after.balance.expect("balance present");
    assert_eq!(bal.nano_ergs, 0);
    assert!(bal.tokens.is_empty());
}

#[test]
fn rollback_drops_token_amounts_added_by_apply() {
    // Apply puts a token bundle onto the owner's balance; rollback
    // calls `subtract_box` with the same deltas, which drives both
    // entries to zero and removes them (`BalanceInfo::subtract_box`).
    let (store, _tmp) = open_store();

    let token_a = Digest32::from_bytes([0xAA; 32]);
    let token_b = Digest32::from_bytes([0xBB; 32]);
    let tx = Transaction {
        inputs: vec![fake_input(0xCC)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            1_000_000,
            1,
            vec![
                Token {
                    token_id: token_a,
                    amount: 5,
                },
                Token {
                    token_id: token_b,
                    amount: 7,
                },
            ],
        )],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
    let th = tree_hash_of(&size_delimited_tree());
    let bal_after_apply = store.read_address(&th).unwrap().unwrap().balance.unwrap();
    assert_eq!(bal_after_apply.tokens, vec![(token_a, 5), (token_b, 7)]);

    rollback_one_block(&store, &meta1, &block).unwrap();
    let bal_after_rollback = store.read_address(&th).unwrap().unwrap().balance.unwrap();
    assert_eq!(bal_after_rollback.nano_ergs, 0);
    assert!(bal_after_rollback.tokens.is_empty());
}

#[test]
fn apply_then_rollback_then_reapply_preserves_balance_byte_for_byte() {
    // Round-trip robustness for the balance accumulator: applying the
    // same block twice (apply -> rollback -> apply) lands on the same
    // serialized address record.
    let (store, _tmp) = open_store();

    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_500_000, 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: sealed_box_id(&tx_a, 0),
            spending_proof: SpendingProof::new(vec![0x09], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(800_000, 2), candidate(50_000, 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    let meta2_a = apply_block(&store, &meta1, &block2).unwrap();
    let th = tree_hash_of(&size_delimited_tree());
    let snap_addr = store.read_address(&th).unwrap().unwrap();

    rollback_one_block(&store, &meta2_a, &block2).unwrap();
    let _meta2_b = apply_block(&store, &meta1, &block2).unwrap();

    assert_eq!(store.read_address(&th).unwrap().unwrap(), snap_addr);
}

fn unique_input(idx: u32) -> Input {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&idx.to_be_bytes());
    Input {
        box_id: Digest32::from_bytes(bytes),
        spending_proof: SpendingProof::new(vec![0xAB], ContextExtension::empty()).unwrap(),
    }
}

#[test]
fn rollback_undoes_box_spill_via_merge_back_clearing_segments_row() {
    use ergo_indexer::segment::SEGMENT_THRESHOLD;
    use ergo_indexer::segment_id::box_segment_id;

    let (store, _tmp) = open_store();
    let n = SEGMENT_THRESHOLD + 1;
    let outs: Vec<_> = (0..n).map(|i| candidate(1_000 + i as u64, 1)).collect();
    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: outs,
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    assert!(store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .is_some());

    rollback_one_block(&store, &meta1, &block).unwrap();

    // Always-upsert: the address record stays on disk after rollback,
    // but its segment is empty and the spill row is gone.
    let addr = store.read_address(&th).unwrap().expect("address kept");
    assert!(addr.segment.boxes.is_empty());
    assert_eq!(addr.segment.box_segment_count, 0);
    assert!(
        store
            .read_spill_segment(&box_segment_id(&th, 0))
            .unwrap()
            .is_none(),
        "spill 0 must be removed from SEGMENTS table on rollback"
    );
}

#[test]
fn rollback_undoes_tx_segment_spill_via_merge_back() {
    use ergo_indexer::segment::SEGMENT_THRESHOLD;
    use ergo_indexer::segment_id::{box_segment_id, tx_segment_id};

    let (store, _tmp) = open_store();
    let n = SEGMENT_THRESHOLD + 1;
    let txs: Vec<Transaction> = (0..n as u32)
        .map(|i| Transaction {
            inputs: vec![unique_input(i)],
            data_inputs: vec![],
            output_candidates: vec![candidate(1_000_000, 1)],
        })
        .collect();
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: &txs,
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    assert!(store
        .read_spill_segment(&tx_segment_id(&th, 0))
        .unwrap()
        .is_some());
    assert!(store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .is_some());

    rollback_one_block(&store, &meta1, &block).unwrap();

    let addr = store.read_address(&th).unwrap().expect("address kept");
    assert!(addr.segment.txs.is_empty());
    assert_eq!(addr.segment.tx_segment_count, 0);
    assert!(addr.segment.boxes.is_empty());
    assert_eq!(addr.segment.box_segment_count, 0);
    assert!(store
        .read_spill_segment(&tx_segment_id(&th, 0))
        .unwrap()
        .is_none());
    assert!(store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .is_none());
}

#[test]
fn rollback_undoes_sign_flip_in_spill_restoring_positive_global_index() {
    use ergo_indexer::segment::SEGMENT_THRESHOLD;
    use ergo_indexer::segment_id::box_segment_id;

    let (store, _tmp) = open_store();
    let n = SEGMENT_THRESHOLD + 88;
    let outs: Vec<_> = (0..n).map(|i| candidate(1_000 + i as u64, 1)).collect();
    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: outs,
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let spent_id = sealed_box_id(&tx_a, 100);
    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: spent_id,
            spending_proof: SpendingProof::new(vec![0x01], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(500_000, 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    let meta2 = apply_block(&store, &meta1, &block2).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    let pre = store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .unwrap();
    assert_eq!(pre.boxes[100], -100);

    rollback_one_block(&store, &meta2, &block2).unwrap();

    // Block 1 stays applied; spill 0's flipped entry is unflipped.
    let post = store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .unwrap();
    assert_eq!(post.boxes[100], 100);
    assert_eq!(post.boxes[99], 99);
    assert_eq!(post.boxes[101], 101);
}

#[test]
fn apply_rollback_reapply_with_spill_preserves_address_and_spill_byte_for_byte() {
    use ergo_indexer::segment::SEGMENT_THRESHOLD;
    use ergo_indexer::segment_id::box_segment_id;

    let (store, _tmp) = open_store();
    let n = SEGMENT_THRESHOLD + 88;
    let outs: Vec<_> = (0..n).map(|i| candidate(1_000 + i as u64, 1)).collect();
    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: outs,
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
    let th = tree_hash_of(&size_delimited_tree());
    let addr_before = store.read_address(&th).unwrap().unwrap();
    let spill_before = store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .unwrap();

    let meta_post_rollback = rollback_one_block(&store, &meta1, &block).unwrap();
    let _ = apply_block(&store, &meta_post_rollback, &block).unwrap();

    let addr_after = store.read_address(&th).unwrap().unwrap();
    let spill_after = store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .unwrap();
    assert_eq!(addr_before, addr_after);
    assert_eq!(spill_before, spill_after);
}

// ----- corruption-detection -----

/// Rollback consumes the undo row before mutating any other table. A
/// malformed undo row with trailing bytes must surface as
/// `UndoEntryMalformed::TrailingBytes` and leave meta + the undo row
/// intact so the operator can inspect.
#[test]
fn rollback_halts_on_malformed_undo_row_with_trailing_bytes() {
    use redb::{Database, TableDefinition};
    use std::path::PathBuf;

    const INDEXER_UNDO_TEST: TableDefinition<u64, &'static [u8]> =
        TableDefinition::new("indexer_undo");

    let tmp = TempDir::new().unwrap();
    let path: PathBuf = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();

    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1)],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    // Read the valid undo row and append trailing garbage.
    let valid_undo = store
        .read_undo(1)
        .unwrap()
        .expect("undo present after apply");
    let mut corrupted = valid_undo.encode();
    let consumed = corrupted.len();
    corrupted.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    // Drop the store so we can reopen the raw redb file.
    drop(store);
    {
        let db = Database::open(&path).unwrap();
        let wtxn = db.begin_write().unwrap();
        {
            let mut t = wtxn.open_table(INDEXER_UNDO_TEST).unwrap();
            t.insert(1u64, corrupted.as_slice()).unwrap();
        }
        wtxn.commit().unwrap();
    }
    let (store, _) = IndexerStore::open(&path).unwrap();

    let meta_before = store.read_meta().unwrap();
    let err = rollback_one_block(&store, &meta1, &block)
        .expect_err("rollback must halt on corrupted undo row");
    assert!(
        matches!(
            err,
            IndexerError::UndoEntryMalformed {
                reason: ergo_indexer::error::UndoEntryMalformedReason::TrailingBytes {
                    expected, got,
                },
            } if expected == consumed && got == consumed + 4,
        ),
        "expected UndoEntryMalformed::TrailingBytes({consumed}, {}), got {err:?}",
        consumed + 4,
    );

    // Persistence invariant: meta and the corrupted undo row must be
    // untouched so an operator can repair from a known state.
    assert_eq!(store.read_meta().unwrap(), meta_before);
    let post_err = store
        .read_undo(1)
        .expect_err("corrupted undo row stayed on disk after the halt");
    assert!(
        matches!(post_err, IndexerError::UndoEntryMalformed { .. }),
        "corrupted undo row must still fail to decode consistently, got {post_err:?}",
    );
}

/// Rollback calls `remove_unspent` on the outputs of the rolled-back
/// block. If that row is already absent — a real indexer/storage-rent
/// index desync — the hard-fail must surface as `StorageRentDesync`
/// rather than silently no-op.
#[test]
fn rollback_halts_on_storage_rent_desync_when_unspent_row_pre_removed() {
    use redb::{Database, TableDefinition};
    use std::path::PathBuf;

    const UNSPENT_BY_CREATION_HEIGHT_TEST: TableDefinition<(u32, i64), &'static [u8]> =
        TableDefinition::new("unspent_by_creation_height");

    let tmp = TempDir::new().unwrap();
    let path: PathBuf = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();

    let tx = Transaction {
        inputs: vec![fake_input(0xCD)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 7)],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    // The output's storage-rent row exists at (creation_height=7,
    // global_box_index=0). Manually drop it to simulate a desync —
    // rollback's `remove_unspent` on that output should hard-fail.
    drop(store);
    {
        let db = Database::open(&path).unwrap();
        let wtxn = db.begin_write().unwrap();
        {
            let mut t = wtxn.open_table(UNSPENT_BY_CREATION_HEIGHT_TEST).unwrap();
            let removed = t.remove((7u32, 0i64)).unwrap();
            assert!(removed.is_some(), "test fixture: row must exist pre-drop");
        }
        wtxn.commit().unwrap();
    }
    let (store, _) = IndexerStore::open(&path).unwrap();

    let err = rollback_one_block(&store, &meta1, &block)
        .expect_err("rollback must halt on storage-rent desync");
    assert!(
        matches!(
            err,
            IndexerError::StorageRentDesync {
                creation_height: 7,
                global_box_index: 0,
            }
        ),
        "expected StorageRentDesync{{7, 0}}, got {err:?}",
    );
}
