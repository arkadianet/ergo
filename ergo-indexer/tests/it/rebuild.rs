//! Integration test for the chain-free secondary-index rebuild
//! (`rebuild_secondary_indexes`).
//!
//! Confirms the rebuild re-derives the template (and token) box-segments from
//! the intact primary tables, reproducing EXACTLY what a fresh linear apply
//! built — including the sign-flip on spent boxes — and that it leaves the
//! PRIMARY address index untouched. This is the engine that restores full
//! correctness after a tolerated `SegmentEntryMissing` drift, without a full
//! chain reindex.

use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{template_hash_from_bytes, write_ergo_tree, ErgoTree};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::{Body, Expr};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_ser::token::Token;
use ergo_ser::transaction::{transaction_id, Transaction};
use tempfile::TempDir;

use ergo_indexer::{
    apply_block, rebuild_secondary_indexes, IndexerBlock, IndexerMeta, IndexerStore, TokenId,
};

fn parseable_tree_true() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
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
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(false)),
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

fn tree_hash_of(tree: &ErgoTree) -> Digest32 {
    ergo_primitives::digest::blake2b256(&tree_bytes(tree))
}

fn candidate_with_tree(value: u64, tree: ErgoTree, height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(value, tree, height, vec![], AdditionalRegisters::empty()).unwrap()
}

fn candidate_with_tokens(
    value: u64,
    tree: ErgoTree,
    height: u32,
    tokens: Vec<Token>,
) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(value, tree, height, tokens, AdditionalRegisters::empty()).unwrap()
}

fn fake_input(box_id_seed: u8) -> Input {
    Input {
        box_id: Digest32::from_bytes([box_id_seed; 32]),
        spending_proof: SpendingProof::new(vec![0xAB, 0xCD, 0xEF], ContextExtension::empty())
            .unwrap(),
    }
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

fn open_store() -> (IndexerStore, TempDir) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();
    (store, tmp)
}

#[test]
fn rebuild_reproduces_template_segments_including_the_spent_flip() {
    let (store, _tmp) = open_store();
    let tree = parseable_tree_true();
    let template = template_hash_of(&tree);
    let address = tree_hash_of(&tree);

    // Block 1: three outputs to the same template → global indices 0, 1, 2.
    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![
            candidate_with_tree(1_000_000, tree.clone(), 1),
            candidate_with_tree(2_000_000, tree.clone(), 1),
            candidate_with_tree(3_000_000, tree.clone(), 1),
        ],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    // Block 2: spend the gi=2 output → a clean non-zero sign-flip in the segment.
    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: sealed_box_id(&tx_a, 2),
            spending_proof: SpendingProof::new(vec![0xCA, 0xFE], ContextExtension::empty())
                .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tree(2_900_000, parseable_tree_false(), 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    apply_block(&store, &meta1, &block2).unwrap();

    // Snapshot the live (correct) state.
    let template_before = store.read_template_box_entries(&template).unwrap().unwrap();
    let address_before = store.read_address_box_entries(&address).unwrap().unwrap();
    assert_eq!(
        template_before,
        vec![0, 1, -2],
        "sanity: two unspent + one spent (flipped) entry"
    );

    // Run the chain-free rebuild: it WIPES the template/token segments and
    // re-derives them from the primary box table.
    rebuild_secondary_indexes(&store).unwrap();

    // Template segment must be reproduced byte-for-byte, including the flip.
    let template_after = store.read_template_box_entries(&template).unwrap().unwrap();
    assert_eq!(
        template_after, template_before,
        "rebuild must reproduce the template segment exactly (incl. the spent flip)"
    );

    // The PRIMARY address index must be untouched by the rebuild.
    let address_after = store.read_address_box_entries(&address).unwrap().unwrap();
    assert_eq!(
        address_after, address_before,
        "rebuild must not modify the address index"
    );

    // The repair marker must be clear after a successful rebuild.
    assert!(
        !store.secondary_repair_pending().unwrap(),
        "rebuild must clear the repair-pending marker on success"
    );
    assert_eq!(
        store.secondary_repair_next_gi().unwrap(),
        None,
        "rebuild must clear the checkpoint on success"
    );
}

#[test]
fn rebuild_reproduces_token_segments_and_preserves_token_metadata() {
    // Token coverage for the rebuild: the wipe must reset only the token's
    // box-SEGMENT (re-derived in Phase 1) while PRESERVING the IndexedToken
    // metadata record (creating_box_id / emission / name / ...), and the
    // re-derived segment must reproduce the spent sign-flip exactly.
    let (store, _tmp) = open_store();
    let tree = parseable_tree_true();

    // Block 1: mint token T (id == first input's box_id, so the EIP-4 mint
    // predicate fires) into three outputs → token segment [0, 1, 2] plus an
    // IndexedToken metadata record.
    let token_id = TokenId::from_bytes([0xAA; 32]);
    let tok = |amount| Token { token_id, amount };
    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![
            candidate_with_tokens(1_000_000, tree.clone(), 1, vec![tok(10)]),
            candidate_with_tokens(2_000_000, tree.clone(), 1, vec![tok(20)]),
            candidate_with_tokens(3_000_000, tree.clone(), 1, vec![tok(30)]),
        ],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    // Block 2: spend the gi=2 token-bearing output → a clean non-zero sign-flip
    // in the token segment.
    let tx_b = Transaction {
        inputs: vec![Input {
            box_id: sealed_box_id(&tx_a, 2),
            spending_proof: SpendingProof::new(vec![0xCA, 0xFE], ContextExtension::empty())
                .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tree(2_900_000, parseable_tree_false(), 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    apply_block(&store, &meta1, &block2).unwrap();

    // Snapshot the live (correct) token segment + metadata record.
    let token_before = store.read_token_box_entries(&token_id).unwrap().unwrap();
    let record_before = store.read_token(&token_id).unwrap().unwrap();
    assert_eq!(
        token_before,
        vec![0, 1, -2],
        "sanity: two unspent + one spent (flipped) token entry"
    );

    rebuild_secondary_indexes(&store).unwrap();

    // Token segment must be reproduced byte-for-byte, including the flip.
    let token_after = store.read_token_box_entries(&token_id).unwrap().unwrap();
    assert_eq!(
        token_after, token_before,
        "rebuild must reproduce the token segment exactly (incl. the spent flip)"
    );

    // Token METADATA must survive the wipe untouched — only the box-segment is
    // reset + re-derived, never the mint record fields.
    let record_after = store.read_token(&token_id).unwrap().unwrap();
    assert_eq!(
        record_after, record_before,
        "rebuild must preserve token metadata (only the box-segment is re-derived)"
    );

    assert!(
        !store.secondary_repair_pending().unwrap(),
        "rebuild must clear the repair-pending marker on success"
    );
    assert_eq!(
        store.secondary_repair_next_gi().unwrap(),
        None,
        "rebuild must clear the checkpoint on success"
    );
}
