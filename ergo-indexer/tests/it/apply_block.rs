//! Integration tests for `apply_block`.
//!
//! Builds synthetic blocks, applies them through the public `IndexerStore`
//! surface, and asserts the on-disk state matches the apply contract:
//! counter assignment, genesis skip, spend stamping with positive
//! global_index, NUMERIC_* maps, meta + undo.

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

use ergo_indexer::{apply_block, IndexerBlock, IndexerError, IndexerMeta, IndexerStore};

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

/// Distinct ErgoTree wrapping a `false` constant — different bytes
/// from `size_delimited_tree`, so different `tree_hash`. Useful for
/// tests that need two non-colliding owner addresses in the same block.
fn size_delimited_tree_false() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(false),
        } as Body,
    }
}

fn tree_hash_of(tree: &ErgoTree) -> Digest32 {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, tree).unwrap();
    ergo_primitives::digest::blake2b256(&w.result())
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

fn candidate_with_tree(value: u64, tree: ErgoTree, height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(value, tree, height, vec![], AdditionalRegisters::empty()).unwrap()
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
fn apply_genesis_block_skips_input_lookup_and_assigns_counters() {
    let (store, _tmp) = open_store();
    let meta0 = store.read_meta().unwrap();
    assert_eq!(meta0, IndexerMeta::empty());

    // Genesis tx: 1 phantom input (skipped because height==1), 2 outputs.
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

    let meta1 = apply_block(&store, &meta0, &block).unwrap();

    assert_eq!(meta1.indexed_height, 1);
    assert_eq!(meta1.indexed_header_id, Some(header_id));
    assert_eq!(meta1.global_tx_index, 1);
    assert_eq!(meta1.global_box_index, 2);

    // Round-trip via the persisted meta (post-commit).
    assert_eq!(store.read_meta().unwrap(), meta1);

    // NUMERIC_BOX[0] -> output[0].box_id, NUMERIC_BOX[1] -> output[1].box_id.
    let out0_id = sealed_box_id(&tx, 0);
    let out1_id = sealed_box_id(&tx, 1);
    assert_eq!(store.read_numeric_box(0).unwrap(), Some(out0_id));
    assert_eq!(store.read_numeric_box(1).unwrap(), Some(out1_id));
    assert_eq!(store.read_numeric_box(2).unwrap(), None);

    // Per-output IndexedErgoBox rows: positive global_index, no spending.
    let b0 = store.read_box(&out0_id).unwrap().expect("output 0");
    assert_eq!(b0.global_index, 0);
    assert_eq!(b0.inclusion_height, 1);
    assert!(!b0.is_spent());

    let b1 = store.read_box(&out1_id).unwrap().expect("output 1");
    assert_eq!(b1.global_index, 1);
    assert!(!b1.is_spent());

    // Tx record: input_nums empty (genesis skip), output_nums = [0, 1].
    let tx_id = transaction_id(&tx).unwrap();
    let rec = store.read_tx(tx_id.as_digest()).unwrap().expect("tx");
    assert_eq!(rec.global_index, 0);
    assert_eq!(rec.input_nums, Vec::<i64>::new());
    assert_eq!(rec.output_nums, vec![0i64, 1]);
    assert_eq!(rec.height, 1);
    assert_eq!(rec.index_in_block, 0);

    // Undo entry recorded under height 1 with empty prev state.
    let undo = store.read_undo(1).unwrap().expect("undo entry");
    assert_eq!(undo.prev_indexed_header_id, None);
    assert_eq!(undo.prev_global_tx_index, 0);
    assert_eq!(undo.prev_global_box_index, 0);
}

#[test]
fn second_block_spends_first_blocks_output_with_positive_global_index_preserved() {
    let (store, _tmp) = open_store();

    // Block 1: genesis-ish, produces 2 outputs.
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
    let spent_id = sealed_box_id(&tx_a, 0);

    // Block 2: tx spending block 1's output 0.
    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: spent_id,
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

    assert_eq!(meta2.indexed_height, 2);
    assert_eq!(meta2.global_tx_index, 2);
    assert_eq!(meta2.global_box_index, 3);

    // Spent box: global_index unchanged at 0; spending fields populated.
    let spent = store.read_box(&spent_id).unwrap().expect("spent box");
    assert_eq!(spent.global_index, 0, "box record stays positive on spend");
    assert!(spent.is_spent());
    assert_eq!(spent.spending_height, Some(2));
    let tx_b_id = transaction_id(&tx_b).unwrap();
    assert_eq!(spent.spending_tx_id, Some(*tx_b_id.as_digest()));
    assert!(spent.spending_proof.is_some());

    // Other block-1 output untouched.
    let other_id = sealed_box_id(&tx_a, 1);
    let other = store.read_box(&other_id).unwrap().expect("other output");
    assert!(!other.is_spent());

    // Block 2 tx record: input_nums carries the spent box's positive global_index.
    let rec = store
        .read_tx(tx_b_id.as_digest())
        .unwrap()
        .expect("tx_b record");
    assert_eq!(rec.input_nums, vec![0i64]);
    assert_eq!(rec.output_nums, vec![2i64]);
    assert_eq!(rec.data_inputs, vec![Digest32::from_bytes([0x55; 32])]);
    assert_eq!(rec.global_index, 1);
    assert_eq!(rec.height, 2);

    // Undo entry under height 2 records meta1 as the prev state.
    let undo = store.read_undo(2).unwrap().expect("undo");
    assert_eq!(undo.prev_indexed_header_id, meta1.indexed_header_id);
    assert_eq!(undo.prev_global_tx_index, meta1.global_tx_index);
    assert_eq!(undo.prev_global_box_index, meta1.global_box_index);
}

#[test]
fn apply_block_with_height_mismatch_errors_without_mutating_meta() {
    let (store, _tmp) = open_store();
    let meta0 = store.read_meta().unwrap();

    // Skip ahead — meta is at 0, block claims height 5.
    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(100_000, 5)],
    };
    let block = IndexerBlock {
        height: 5,
        header_id: Digest32::from_bytes([0xEE; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    let err = apply_block(&store, &meta0, &block).unwrap_err();
    assert!(
        matches!(err, IndexerError::HeightMismatch { .. }),
        "got {err:?}"
    );
    // Meta untouched on rejection.
    assert_eq!(store.read_meta().unwrap(), meta0);
}

#[test]
fn missing_input_after_genesis_returns_input_missing_and_aborts_txn() {
    let (store, _tmp) = open_store();

    // Block 1: produce a known output (via genesis skip).
    let tx_a = Transaction {
        inputs: vec![fake_input(0x11)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0xA1; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    // Block 2: input references an unknown box → InputMissing, txn aborts.
    let tx_b = Transaction {
        inputs: vec![fake_input(0x99)],
        data_inputs: vec![],
        output_candidates: vec![candidate(500_000, 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0xA2; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    let err = apply_block(&store, &meta1, &block2).unwrap_err();
    assert!(
        matches!(err, IndexerError::InputMissing { height: 2, .. }),
        "expected InputMissing at height 2, got {err:?}"
    );

    // Atomicity: meta still mirrors block 1 only.
    assert_eq!(store.read_meta().unwrap(), meta1);
    // Tx-b record should not have leaked through.
    let tx_b_id = transaction_id(&tx_b).unwrap();
    assert!(store.read_tx(tx_b_id.as_digest()).unwrap().is_none());
    // Output box-id of tx_b should not have been written.
    let leaked = sealed_box_id(&tx_b, 0);
    assert!(store.read_box(&leaked).unwrap().is_none());
}

#[test]
fn protocol_genesis_input_is_absorbed_silently_and_rolls_back_cleanly() {
    // Mainnet h=3850 reproducer: the foundation box
    // (5527430474b673e4aafb08e0079c639de23e6a17e87edd00f78662b43c88aeda) is
    // seeded by the protocol before block 1 and never appears in
    // `box_table`. Pre-fix, its first spend halted the indexer with
    // `InputMissing`. Scala's `ExtraIndexer.scala:331` `log.warn`
    // silently absorbs these spends; we mirror that for the 3 known
    // protocol-genesis IDs only. Rollback must be a symmetric no-op
    // for the same input.
    use ergo_indexer::rollback_one_block;
    use ergo_indexer_types::PROTOCOL_GENESIS_BOX_IDS_MAINNET;

    let (store, _tmp) = open_store();

    // Block 1: bootstrap a normal output so the indexer's first
    // post-genesis state isn't empty.
    let tx_a = Transaction {
        inputs: vec![fake_input(0x11)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0xB1; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    // Block 2: spend the foundation protocol-genesis box. Apply must
    // succeed without `InputMissing` and the tx-record's `input_nums`
    // must carry 0 for that slot (matches Scala `Array.ofDim[Long]`
    // default — ExtraIndexer.scala:312).
    let foundation_id = Digest32::from_bytes(PROTOCOL_GENESIS_BOX_IDS_MAINNET[2]);
    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: foundation_id,
            spending_proof: SpendingProof::new(vec![0xFE, 0xED], ContextExtension::empty())
                .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(900_000, 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0xB2; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    let meta2 = apply_block(&store, &meta1, &block2).unwrap();
    assert_eq!(meta2.indexed_height, 2);
    assert_eq!(meta2.global_box_index, 2); // 1 from block1 + 1 from block2 output

    let tx_b_id = transaction_id(&tx_b).unwrap();
    let rec = store
        .read_tx(tx_b_id.as_digest())
        .unwrap()
        .expect("tx_b recorded");
    assert_eq!(
        rec.input_nums,
        vec![0i64],
        "Scala-default for unindexed input"
    );

    // Rollback must succeed too — the symmetric path skips the missing
    // protocol-genesis input rather than erroring on the lookup.
    let meta_after_rollback = rollback_one_block(&store, &meta2, &block2).unwrap();
    assert_eq!(meta_after_rollback.indexed_height, 1);
    assert_eq!(meta_after_rollback, meta1);
    assert!(store.read_tx(tx_b_id.as_digest()).unwrap().is_none());
}

#[test]
fn missing_input_for_non_whitelisted_id_after_genesis_still_halts() {
    // Sister test to `protocol_genesis_input_is_absorbed_silently...`:
    // confirms the bypass is keyed strictly on the 3 mainnet
    // protocol-genesis IDs. Any other unindexed box id must still trip
    // `InputMissing` so a real chain/indexer divergence is not silently
    // swallowed.
    use ergo_indexer_types::PROTOCOL_GENESIS_BOX_IDS_MAINNET;

    let (store, _tmp) = open_store();

    let tx_a = Transaction {
        inputs: vec![fake_input(0x11)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0xC1; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    // Construct an id that is provably NOT one of the 3 whitelisted IDs
    // (start with a unique seed that doesn't collide with any prefix).
    let bogus = Digest32::from_bytes([0x99; 32]);
    assert!(
        !PROTOCOL_GENESIS_BOX_IDS_MAINNET
            .iter()
            .any(|id| id == bogus.as_bytes()),
        "test setup: bogus id must not be a protocol-genesis id"
    );

    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: bogus,
            spending_proof: SpendingProof::new(vec![0xDE, 0xAD], ContextExtension::empty())
                .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(500_000, 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0xC2; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    let err = apply_block(&store, &meta1, &block2).unwrap_err();
    assert!(
        matches!(err, IndexerError::InputMissing { height: 2, .. }),
        "expected InputMissing for non-whitelisted id, got {err:?}"
    );
}

#[test]
fn applies_two_txs_in_order_and_assigns_counters_consecutively() {
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

    let tx0_id = transaction_id(&tx0).unwrap();
    let tx1_id = transaction_id(&tx1).unwrap();
    let r0 = store.read_tx(tx0_id.as_digest()).unwrap().unwrap();
    let r1 = store.read_tx(tx1_id.as_digest()).unwrap().unwrap();
    assert_eq!(r0.global_index, 0);
    assert_eq!(r0.index_in_block, 0);
    assert_eq!(r0.output_nums, vec![0i64, 1]);
    assert_eq!(r1.global_index, 1);
    assert_eq!(r1.index_in_block, 1);
    assert_eq!(r1.output_nums, vec![2i64]);

    // NUMERIC_TX maps both.
    assert_eq!(store.read_numeric_tx(0).unwrap(), Some(*tx0_id.as_digest()));
    assert_eq!(store.read_numeric_tx(1).unwrap(), Some(*tx1_id.as_digest()));
}

#[test]
fn apply_creates_indexed_address_with_summed_balance_for_outputs_to_same_tree() {
    // Two outputs to the same ErgoTree → one IndexedAddress record
    // with `nano_ergs = sum(values)`.
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
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    let addr = store.read_address(&th).unwrap().expect("address present");
    let balance = addr
        .balance
        .expect("balance present on apply-touched address");
    assert_eq!(balance.nano_ergs, 3_500_000);
    assert!(balance.tokens.is_empty());
}

#[test]
fn apply_keeps_two_addresses_distinct_under_two_distinct_trees() {
    // Outputs split across two ErgoTrees → two IndexedAddress records
    // with non-mixed balances. Guards against any accidental shared-key
    // collision (e.g. computing tree_hash from the wrong bytes).
    let (store, _tmp) = open_store();
    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![
            candidate_with_tree(1_000_000, size_delimited_tree(), 1),
            candidate_with_tree(7_500_000, size_delimited_tree_false(), 1),
        ],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let th_true = tree_hash_of(&size_delimited_tree());
    let th_false = tree_hash_of(&size_delimited_tree_false());
    assert_ne!(th_true, th_false, "trees must hash to distinct keys");

    let bal_true = store
        .read_address(&th_true)
        .unwrap()
        .unwrap()
        .balance
        .unwrap();
    let bal_false = store
        .read_address(&th_false)
        .unwrap()
        .unwrap()
        .balance
        .unwrap();
    assert_eq!(bal_true.nano_ergs, 1_000_000);
    assert_eq!(bal_false.nano_ergs, 7_500_000);
}

#[test]
fn apply_then_spend_decrements_owner_balance() {
    // Block 1 creates two outputs to one tree (3.5M total). Block 2
    // spends one of them (1M). Owner balance must end at 2.5M.
    let (store, _tmp) = open_store();
    let tx_a = Transaction {
        inputs: vec![fake_input(0xFF)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_500_000, 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();
    let spent_id = sealed_box_id(&tx_a, 0); // 1M output

    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: spent_id,
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
    apply_block(&store, &meta1, &block2).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    let bal = store.read_address(&th).unwrap().unwrap().balance.unwrap();
    // Block 1: +1M +2.5M = 3.5M; block 2: -1M (spend) +0.9M (output) = 3.4M
    assert_eq!(bal.nano_ergs, 3_400_000);
}

#[test]
fn apply_records_token_bundle_on_owner_address() {
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
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    let bal = store.read_address(&th).unwrap().unwrap().balance.unwrap();
    assert_eq!(bal.nano_ergs, 1_000_000);
    assert_eq!(bal.tokens, vec![(token_a, 5), (token_b, 7)]);
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
fn apply_block_with_513_outputs_to_one_tree_spills_box_segment_at_threshold() {
    use ergo_indexer::segment::SEGMENT_THRESHOLD;
    use ergo_indexer::segment_id::box_segment_id;

    let (store, _tmp) = open_store();
    let n = SEGMENT_THRESHOLD + 1; // 513
    let outputs: Vec<_> = (0..n).map(|i| candidate(1_000_000 + i as u64, 1)).collect();
    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: outputs,
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    let addr = store.read_address(&th).unwrap().expect("address");

    // Head retains exactly the newest entry; spill 0 carries the oldest 512.
    assert_eq!(addr.segment.boxes, vec![SEGMENT_THRESHOLD as i64]);
    assert_eq!(addr.segment.box_segment_count, 1);

    let spill = store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .expect("spill 0 must be on disk after apply commit");
    assert_eq!(spill.boxes.len(), SEGMENT_THRESHOLD);
    assert_eq!(spill.boxes[0], 0);
    assert_eq!(
        spill.boxes[SEGMENT_THRESHOLD - 1],
        (SEGMENT_THRESHOLD - 1) as i64
    );
}

#[test]
fn apply_block_spending_box_in_spill_negates_sign_in_spill_row() {
    use ergo_indexer::segment::SEGMENT_THRESHOLD;
    use ergo_indexer::segment_id::box_segment_id;

    let (store, _tmp) = open_store();
    // Block 1: 600 outputs → spill 0 has 0..512, head has 88 entries [512..600).
    let n = SEGMENT_THRESHOLD + 88;
    let outs: Vec<_> = (0..n).map(|i| candidate(1_000_000 + i as u64, 1)).collect();
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

    // Block 2: spend output #100 (lives in spill 0 at position 100).
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
    apply_block(&store, &meta1, &block2).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    let spill = store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .expect("spill 0");
    assert_eq!(spill.boxes[100], -100, "spent entry sign-flipped");
    assert_eq!(spill.boxes[99], 99);
    assert_eq!(spill.boxes[101], 101);
}

#[test]
fn apply_block_with_513_single_output_txs_to_one_tree_spills_tx_segment() {
    use ergo_indexer::segment::SEGMENT_THRESHOLD;
    use ergo_indexer::segment_id::tx_segment_id;

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
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    let addr = store.read_address(&th).unwrap().expect("address");

    // 513 single-output txs → both tx-segment AND box-segment cross the threshold.
    assert_eq!(addr.segment.txs, vec![SEGMENT_THRESHOLD as i64]);
    assert_eq!(addr.segment.tx_segment_count, 1);
    assert_eq!(addr.segment.boxes, vec![SEGMENT_THRESHOLD as i64]);
    assert_eq!(addr.segment.box_segment_count, 1);

    let tx_spill = store
        .read_spill_segment(&tx_segment_id(&th, 0))
        .unwrap()
        .expect("tx spill 0");
    assert_eq!(tx_spill.txs.len(), SEGMENT_THRESHOLD);
    assert_eq!(tx_spill.txs[0], 0);
    assert_eq!(
        tx_spill.txs[SEGMENT_THRESHOLD - 1],
        (SEGMENT_THRESHOLD - 1) as i64
    );
}

#[test]
fn apply_two_blocks_can_spill_box_segment_across_block_boundary() {
    use ergo_indexer::segment::SEGMENT_THRESHOLD;
    use ergo_indexer::segment_id::box_segment_id;

    let (store, _tmp) = open_store();
    // Block 1: 400 outputs (under threshold; head fills, no spill).
    let outs1: Vec<_> = (0..400u64).map(|i| candidate(1_000 + i, 1)).collect();
    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: outs1,
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let th = tree_hash_of(&size_delimited_tree());
    let addr1 = store.read_address(&th).unwrap().expect("address");
    assert_eq!(addr1.segment.boxes.len(), 400);
    assert_eq!(addr1.segment.box_segment_count, 0);
    assert!(store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .is_none());

    // Block 2: spend output #100 from block 1 (in head), then create 200
    // more outputs. Total head reaches 600 entries, trips the threshold,
    // and spills the oldest 512 — including the just-flipped entry at
    // position 100.
    let outs2: Vec<_> = (0..200u64).map(|i| candidate(2_000 + i, 2)).collect();
    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: sealed_box_id(&tx_a, 100),
            spending_proof: SpendingProof::new(vec![0xBB], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: outs2,
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    apply_block(&store, &meta1, &block2).unwrap();

    let addr2 = store.read_address(&th).unwrap().expect("address");
    let head_len = 600 - SEGMENT_THRESHOLD;
    assert_eq!(addr2.segment.boxes.len(), head_len);
    assert_eq!(addr2.segment.box_segment_count, 1);
    assert_eq!(addr2.segment.boxes[0], SEGMENT_THRESHOLD as i64);
    assert_eq!(addr2.segment.boxes[head_len - 1], 599);

    let spill = store
        .read_spill_segment(&box_segment_id(&th, 0))
        .unwrap()
        .expect("spill 0");
    assert_eq!(spill.boxes.len(), SEGMENT_THRESHOLD);
    assert_eq!(spill.boxes[0], 0);
    assert_eq!(
        spill.boxes[100], -100,
        "flip-then-spill carries sign into spill row"
    );
    assert_eq!(spill.boxes[101], 101);
    assert_eq!(
        spill.boxes[SEGMENT_THRESHOLD - 1],
        (SEGMENT_THRESHOLD - 1) as i64
    );
}
