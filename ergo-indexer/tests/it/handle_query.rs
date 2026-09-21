//! Integration tests for the `IndexerQuery` impl on `IndexerHandle` —
//! boxes/txs by-id and by-global-index.
//!
//! Builds a synthetic two-block chain via `apply_block`, then asserts the
//! handle's `box_by_id` / `box_by_global_index` / `tx_by_id` /
//! `tx_by_global_index` resolve to the same `IndexedErgoBox` /
//! `IndexedErgoTransaction` records that landed on disk.

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::{Body, Expr};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::transaction::{transaction_id, Transaction};
use tempfile::TempDir;

use ergo_indexer::{
    apply_block, IndexerBlock, IndexerHaltReason, IndexerHandle, IndexerQuery, IndexerStatus,
    IndexerStore,
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

/// Open an empty store wrapped in a fresh `IndexerHandle`. Returns the
/// handle, the underlying tempdir (kept alive), and the genesis +
/// child txs so callers can cross-reference what was indexed.
fn setup_two_block_chain() -> (IndexerHandle, TempDir, Transaction, Transaction) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();
    let handle = IndexerHandle::with_store(store, 0);
    let store = handle.store().unwrap();

    // Genesis block (h=1): 1 phantom input (skipped), 2 outputs.
    let genesis = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_000_000, 1)],
    };
    let header_a = Digest32::from_bytes([0x11; 32]);
    let block_a = IndexerBlock {
        height: 1,
        header_id: header_a,
        transactions: std::slice::from_ref(&genesis),
    };
    let meta0 = store.read_meta().unwrap();
    let meta1 = apply_block(&store, &meta0, &block_a).unwrap();
    handle.set_indexed_height(meta1.indexed_height);

    // Child block (h=2): consumes genesis output 0, creates 1 output.
    let consumed = sealed_box_id(&genesis, 0);
    let child = Transaction {
        inputs: vec![Input {
            box_id: consumed,
            spending_proof: SpendingProof::new(vec![0x12, 0x34], ContextExtension::empty())
                .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(900_000, 2)],
    };
    let header_b = Digest32::from_bytes([0x22; 32]);
    let block_b = IndexerBlock {
        height: 2,
        header_id: header_b,
        transactions: std::slice::from_ref(&child),
    };
    let meta2 = apply_block(&store, &meta1, &block_b).unwrap();
    handle.set_indexed_height(meta2.indexed_height);
    handle.set_status(IndexerStatus::CaughtUp);

    (handle, tmp, genesis, child)
}

// ----- happy path -----

#[test]
fn box_by_id_returns_indexed_record() {
    let (handle, _tmp, genesis, _child) = setup_two_block_chain();
    let box_id = sealed_box_id(&genesis, 1);

    let dto = handle.box_by_id(&box_id).expect("box exists");
    assert_eq!(dto.box_data.candidate.value, 2_000_000);
    assert_eq!(dto.inclusion_height, 1);
    assert!(dto.spending_tx_id.is_none());
    // Genesis outputs get global_index 0, 1 (counters are 0-based).
    assert_eq!(dto.global_index, 1);
}

#[test]
fn box_by_id_returns_spent_record_with_spending_fields_set() {
    let (handle, _tmp, genesis, child) = setup_two_block_chain();
    let spent_box = sealed_box_id(&genesis, 0);

    let dto = handle.box_by_id(&spent_box).expect("spent box exists");
    assert!(dto.is_spent());
    assert_eq!(dto.spending_height, Some(2));
    let child_tx_id = transaction_id(&child).unwrap();
    assert_eq!(dto.spending_tx_id, Some(*child_tx_id.as_digest()));
    // global_index unchanged on spend (genesis output 0 keeps 0).
    assert_eq!(dto.global_index, 0);
}

#[test]
fn box_by_id_returns_none_for_unknown_id() {
    let (handle, _tmp, _genesis, _child) = setup_two_block_chain();
    let unknown = Digest32::from_bytes([0xFF; 32]);
    assert!(handle.box_by_id(&unknown).is_none());
}

#[test]
fn box_by_global_index_round_trips_through_numeric_table() {
    let (handle, _tmp, genesis, _child) = setup_two_block_chain();

    // Output 0 of genesis was assigned global_index 0.
    let dto0 = handle.box_by_global_index(0).expect("global_index 0");
    assert_eq!(dto0.box_data.candidate.value, 1_000_000);
    assert_eq!(dto0.inclusion_height, 1);

    // Output 1 of genesis was assigned global_index 1.
    let dto1 = handle.box_by_global_index(1).expect("global_index 1");
    assert_eq!(dto1.box_data.candidate.value, 2_000_000);

    // Child tx's only output → global_index 2.
    let dto2 = handle.box_by_global_index(2).expect("global_index 2");
    assert_eq!(dto2.box_data.candidate.value, 900_000);
    let _ = genesis;

    // Cross-check with by-id resolution.
    let by_id = handle.box_by_id(&dto1.box_data.box_id().unwrap()).unwrap();
    assert_eq!(by_id.global_index, dto1.global_index);
}

#[test]
fn box_by_global_index_returns_none_for_unknown_n() {
    let (handle, _tmp, _g, _c) = setup_two_block_chain();
    assert!(handle.box_by_global_index(999).is_none());
}

#[test]
fn tx_by_id_returns_indexed_record() {
    let (handle, _tmp, genesis, child) = setup_two_block_chain();
    let g_id = transaction_id(&genesis).unwrap();
    let c_id = transaction_id(&child).unwrap();

    let g_dto = handle.tx_by_id(g_id.as_digest()).expect("genesis tx");
    assert_eq!(g_dto.height, 1);
    assert_eq!(g_dto.global_index, 0);
    assert_eq!(g_dto.output_nums, vec![0, 1]);
    // genesis has no input lookup (height==1) so input_nums is empty.
    assert!(g_dto.input_nums.is_empty());

    let c_dto = handle.tx_by_id(c_id.as_digest()).expect("child tx");
    assert_eq!(c_dto.height, 2);
    assert_eq!(c_dto.global_index, 1);
    assert_eq!(c_dto.input_nums, vec![0]); // consumed genesis output 0 (global_index 0)
    assert_eq!(c_dto.output_nums, vec![2]);
}

#[test]
fn tx_by_id_returns_none_for_unknown_id() {
    let (handle, _tmp, _g, _c) = setup_two_block_chain();
    let unknown = Digest32::from_bytes([0xFF; 32]);
    assert!(handle.tx_by_id(&unknown).is_none());
}

#[test]
fn tx_by_global_index_round_trips_through_numeric_table() {
    let (handle, _tmp, genesis, child) = setup_two_block_chain();

    let dto0 = handle.tx_by_global_index(0).expect("global tx 0");
    assert_eq!(dto0.id, *transaction_id(&genesis).unwrap().as_digest());
    let dto1 = handle.tx_by_global_index(1).expect("global tx 1");
    assert_eq!(dto1.id, *transaction_id(&child).unwrap().as_digest());
}

#[test]
fn tx_by_global_index_returns_none_for_unknown_n() {
    let (handle, _tmp, _g, _c) = setup_two_block_chain();
    assert!(handle.tx_by_global_index(999).is_none());
}

#[test]
fn halted_handle_returns_none_from_all_read_methods() {
    let h = IndexerHandle::halted(IndexerHaltReason::DbCorruption);
    let unknown_id = Digest32::from_bytes([0xAA; 32]);
    // Halted handles have no store attached — every read short-circuits
    // before opening any redb txn.
    assert!(h.box_by_id(&unknown_id).is_none());
    assert!(h.box_by_global_index(0).is_none());
    assert!(h.tx_by_id(&unknown_id).is_none());
    assert!(h.tx_by_global_index(0).is_none());
}

// `[inherited]` segment-filter quirk:
// the genesis output (`global_index = 0`) is observationally invisible
// to segment-backed unspent queries because both Scala
// (`Segment.scala:247,252,259,263`) and our mirror
// (`handle.rs:298,370,457`) filter `_ > 0`. Since `-0 == 0` the entry
// also cannot be sign-flipped to indicate spend. This test pins that
// behavior on `address_unspent_paged`. The identical filter is reused
// verbatim in `template_unspent_paged` (`handle.rs:370`) and
// `token_unspent_paged` (`handle.rs:457`); slice 2+ extends this
// coverage to those routes once the broader P5 oracle fixtures land.
#[test]
fn genesis_output_global_index_zero_is_invisible_to_unspent_address_query() {
    use ergo_indexer::IndexerQuery;
    use ergo_indexer_types::{Page, SortDir};
    use ergo_primitives::digest::blake2b256;

    let (handle, _tmp, genesis, _child) = setup_two_block_chain();
    // The genesis tx's outputs share one ergo_tree (the
    // size-delimited true-leaf used by the test fixture), so they
    // hash to a single tree_hash. Genesis output 0 has
    // global_index = 0; output 1 has global_index = 1.
    let tree_bytes = genesis.output_candidates[0].ergo_tree_bytes();
    let tree_hash = blake2b256(tree_bytes);

    // Sanity: by-id resolution still finds the global_index = 0 box.
    let by_id = handle.box_by_global_index(0).expect("global_index 0");
    assert_eq!(by_id.global_index, 0);

    // The unspent address query MUST omit the global_index = 0 entry
    // even though it is unspent. This matches Scala's `_ > 0` filter
    // exactly. Output 1 (global_index = 1, unspent) MUST be present.
    let page = Page {
        offset: 0,
        limit: 100,
    };
    let unspent = handle.address_unspent_paged(&tree_hash, page, SortDir::Asc);
    assert!(
        !unspent.iter().any(|b| b.global_index == 0),
        "[inherited] quirk: genesis global_index=0 must be invisible to \
         segment-backed unspent queries; saw it returned by \
         address_unspent_paged"
    );
    assert!(
        unspent.iter().any(|b| b.global_index == 1),
        "non-zero unspent output (global_index=1) must still be visible"
    );
}
