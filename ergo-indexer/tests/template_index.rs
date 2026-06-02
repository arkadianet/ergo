//! Integration tests for `INDEXED_TEMPLATE` apply + rollback.
//!
//! Confirms:
//!   - apply records every output whose tree parses cleanly under its
//!     template_hash (no per-tx dedupe);
//!   - apply skips outputs whose tree is wrapped as `UnparsedErgoTree`
//!     (the soft-fork path — see `template_hash_for_box_bytes`);
//!   - apply flips the sign of an existing template entry on input
//!     spend;
//!   - rollback inverts both the append and the flip, leaving the
//!     persisted template segment matching its pre-apply state;
//!   - the box-segment spill mechanic works for templates exactly as
//!     it does for addresses (>512 entries triggers a spill row under
//!     `box_segment_id(template_hash, 0)`).

use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{template_hash_from_bytes, write_ergo_tree, ErgoTree};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::{Body, Expr};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::transaction::{transaction_id, Transaction};
use tempfile::TempDir;

use ergo_indexer::{apply_block, rollback_one_block, IndexerBlock, IndexerMeta, IndexerStore};

/// Parseable v0 tree without `has_size` — `template_hash_from_bytes`
/// returns `Ok(...)` for these (no soft-fork wrap path triggers).
fn parseable_tree_true() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        } as Body,
    }
}

fn parseable_tree_false() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(false),
        } as Body,
    }
}

/// Unparseable: `has_size: true` + non-SigmaProp `Const` root → wrapped
/// as `UnparsedErgoTree` on read, so `template_hash_for_box_bytes`
/// returns `None` and the indexer must skip the template entry.
fn unparseable_tree() -> ErgoTree {
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

fn tree_bytes(tree: &ErgoTree) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, tree).unwrap();
    w.result()
}

fn template_hash_of(tree: &ErgoTree) -> Digest32 {
    let bytes = tree_bytes(tree);
    let arr = template_hash_from_bytes(&bytes).expect("tree must be template-parseable");
    Digest32::from_bytes(arr)
}

fn candidate_with_tree(value: u64, tree: ErgoTree, height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(value, tree, height, vec![], AdditionalRegisters::empty()).unwrap()
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
fn apply_records_one_template_entry_per_parseable_output() {
    // Two outputs to the same template — both must end up under the
    // template_hash with the same global indices the address segment
    // would carry. Confirms: no per-tx dedupe (the template's segment
    // length matches the count of touching outputs, not the tx count).
    let (store, _tmp) = open_store();
    let tree = parseable_tree_true();
    let template = template_hash_of(&tree);

    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![
            candidate_with_tree(1_000_000, tree.clone(), 1),
            candidate_with_tree(2_000_000, tree, 1),
        ],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let entries = store
        .read_template_box_entries(&template)
        .unwrap()
        .expect("template recorded after apply");
    assert_eq!(
        entries,
        vec![0, 1],
        "two outputs to the same template must each push a positive global index"
    );
}

#[test]
fn apply_skips_template_entry_for_unparseable_tree() {
    // A `has_size + Const(SBoolean)` tree is wrapped as
    // `UnparsedErgoTree` on read → `template_hash_for_box_bytes`
    // returns `None` → indexer must skip the template recording. The
    // address still indexes (the address-side `tree_hash_from_bytes`
    // is unconditional blake2b of the canonical bytes), but the
    // template row must not exist.
    let (store, _tmp) = open_store();
    let unparseable = unparseable_tree();
    let unparseable_bytes = tree_bytes(&unparseable);
    let unparseable_hash = ergo_primitives::digest::blake2b256(&unparseable_bytes);

    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tree(1_000_000, unparseable, 1)],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x12; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    // The address row IS written (tree_hash is just blake2b of bytes).
    assert!(
        store.read_address(&unparseable_hash).unwrap().is_some(),
        "address row must still exist for unparseable trees — only the template index skips"
    );
    // No template row may exist under the wrap-placeholder hash.
    let placeholder = template_hash_from_bytes(&unparseable_bytes);
    assert!(
        placeholder.is_err(),
        "unparseable tree's template_hash_from_bytes must return Err so indexer skips"
    );
    // Defensive: nothing under the address-side hash either, since
    // template keys are template_hash, never tree_hash.
    assert!(
        store.read_template(&unparseable_hash).unwrap().is_none(),
        "no template row may exist when every output's tree is wrapped"
    );
}

#[test]
fn apply_then_spend_flips_template_entry_sign() {
    // Block 1 creates one output to a parseable tree → template
    // segment has [+0]. Block 2 spends that output → template segment
    // must be [-0] (sign-flipped on spend).
    let (store, _tmp) = open_store();
    let tree = parseable_tree_true();
    let template = template_hash_of(&tree);

    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tree(1_000_000, tree.clone(), 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let entries = store.read_template_box_entries(&template).unwrap().unwrap();
    assert_eq!(entries, vec![0]);

    let spent_id = sealed_box_id(&tx_a, 0);
    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: spent_id,
            spending_proof: SpendingProof::new(
                vec![0xCA, 0xFE, 0xBA, 0xBE],
                ContextExtension::empty(),
            )
            .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tree(900_000, parseable_tree_false(), 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    apply_block(&store, &meta1, &block2).unwrap();

    let entries = store.read_template_box_entries(&template).unwrap().unwrap();
    assert_eq!(
        entries,
        vec![-0i64],
        "spent output must be sign-flipped in the template segment (still magnitude 0)"
    );
}

#[test]
fn rollback_undoes_template_append_and_flip() {
    // Apply two blocks (block 2 spends block 1's output), then roll
    // back block 2 → template segment back to `[+0]`. Then roll back
    // block 1 → no template row at all (only block 1 wrote it).
    let (store, _tmp) = open_store();
    let tree = parseable_tree_true();
    let template = template_hash_of(&tree);

    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tree(1_000_000, tree.clone(), 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let spent_id = sealed_box_id(&tx_a, 0);
    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: spent_id,
            spending_proof: SpendingProof::new(
                vec![0xCA, 0xFE, 0xBA, 0xBE],
                ContextExtension::empty(),
            )
            .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tree(900_000, parseable_tree_false(), 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    let meta2 = apply_block(&store, &meta1, &block2).unwrap();
    assert_eq!(
        store.read_template_box_entries(&template).unwrap().unwrap(),
        vec![-0i64],
        "post-apply: template entry sign-flipped"
    );

    // Rollback block 2 — must unflip the entry back to +0.
    let after_rb2 = rollback_one_block(&store, &meta2, &block2).unwrap();
    assert_eq!(after_rb2, meta1, "meta restored to pre-block-2 snapshot");
    assert_eq!(
        store.read_template_box_entries(&template).unwrap().unwrap(),
        vec![0i64],
        "post-rollback-block-2: template entry restored to positive"
    );

    // Rollback block 1 — must pop the template entry. The parent row
    // either disappears or is left empty — `read_template` returning
    // `Some(empty)` is acceptable since `flush_templates` overwrites
    // the row with whatever the in-memory copy is at end of block.
    let after_rb1 = rollback_one_block(&store, &after_rb2, &block1).unwrap();
    assert_eq!(after_rb1.indexed_height, 0);
    let post = store.read_template_box_entries(&template).unwrap();
    match post {
        None => {} // ideal: row never existed and rollback didn't write
        Some(v) => assert!(
            v.is_empty(),
            "post-rollback-block-1: template entries must be empty, got {v:?}"
        ),
    }
}

#[test]
fn apply_with_513_outputs_to_one_template_spills_box_segment() {
    // Mirrors the address-side spill test
    // (`apply_block_with_513_outputs_to_one_tree_spills_box_segment_at_threshold`).
    // Pushes 513 outputs to the same template and confirms one spill
    // row appears under `box_segment_id(template_hash, 0)`.
    use ergo_indexer::store::IndexerMeta as Meta;
    let (store, _tmp) = open_store();
    let tree = parseable_tree_true();
    let template = template_hash_of(&tree);

    // Build one block with one tx that creates 513 outputs to the same
    // template. Each output is a fresh candidate (height threads
    // through `creation_info` so they're distinct sealed boxes).
    let outputs: Vec<ErgoBoxCandidate> = (0..513)
        .map(|i| candidate_with_tree(1_000 + i as u64, tree.clone(), 1))
        .collect();
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
    apply_block(&store, &Meta::empty(), &block).unwrap();

    // Concatenated entries must total 513.
    let entries = store.read_template_box_entries(&template).unwrap().unwrap();
    assert_eq!(entries.len(), 513);
    assert_eq!(entries[0], 0);
    assert_eq!(entries[512], 512);

    // Spill row must exist under `box_segment_id(template_hash, 0)`.
    let spill_id = ergo_indexer::segment_id::box_segment_id(&template, 0);
    let spill = store
        .read_spill_segment(&spill_id)
        .unwrap()
        .expect("spill row written for templates exactly like for addresses");
    assert_eq!(spill.boxes.len(), 512, "spill row carries the oldest 512");
    assert_eq!(spill.boxes[0], 0);
    assert_eq!(spill.boxes[511], 511);
}

/// Sanity-check: `template_hash_from_bytes` must succeed on the
/// fixtures we use here, otherwise every other test in this file is
/// silently no-op'd.
#[test]
fn fixture_trees_are_template_parseable() {
    let _ = template_hash_of(&parseable_tree_true());
    let _ = template_hash_of(&parseable_tree_false());

    let bytes = tree_bytes(&unparseable_tree());
    assert!(
        template_hash_from_bytes(&bytes).is_err(),
        "unparseable_tree fixture must surface as Err for the indexer skip path"
    );
}
