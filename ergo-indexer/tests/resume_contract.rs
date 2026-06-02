//! Cross-session resume equivalence — pins the "indexer is restart-safe"
//! contract across the full per-type state surface, not just one
//! table.
//!
//! Apply-path commits run under `Durability::Eventual`, so recovery on
//! restart is by replay from the chain store, not by guaranteed fsync per
//! block. The resume contract is unchanged in shape — `IndexerHandle::boot`
//! reads the persisted meta, `IndexerTask` rolls back if `header_id_at`
//! diverges, then forward-applies — but it is now *load-bearing* in a way
//! it wasn't when every block fsync'd. This test pins it.
//!
//! Existing close/reopen coverage in `tests/storage_rent_apply.rs:565`
//! asserts the storage-rent table only. This test extends the assertion
//! to every observable read surface flushed inside the durability-shifted
//! apply transaction: `INDEXER_META`, `INDEXER_UNDO` at every applied
//! height, per-output box rows + `NUMERIC_BOX[global_box_index]`, per-tx
//! rows + `NUMERIC_TX[global_tx_index]`, `IndexedAddress` parent +
//! `BalanceInfo` + box/tx segment entries, `IndexedTemplate` parent +
//! box-segment entries, `IndexedToken` parent (mint metadata) + box-segment
//! entries, and `unspent_by_creation_height` rows.

use ergo_indexer::address::IndexedAddress;
use ergo_indexer::segment::Segment;
use ergo_indexer::segment_id::{box_segment_id, token_unique_id};
use ergo_indexer::template::IndexedTemplate;
use ergo_indexer::token::IndexedToken;
use ergo_indexer::{apply_block, IndexerBlock, IndexerMeta, IndexerStore, UndoEntry};
use ergo_indexer_types::{IndexedErgoBox, IndexedErgoTransaction};
use ergo_primitives::digest::{blake2b256, Digest32};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{template_hash_from_bytes, write_ergo_tree, ErgoTree};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::{Body, Expr};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use ergo_ser::transaction::{transaction_id, Transaction};
use tempfile::TempDir;

// ----- helpers -----

/// Template-parseable tree (`has_size: false`). With `has_size: true`,
/// `template_hash_from_bytes` returns `Unparseable` and `apply_block`
/// skips the template entry — see `tests/template_index.rs:60` for the
/// unparseable variant. We need parseable trees here so the snapshot
/// has non-trivial template records to compare.
fn tree_true() -> ErgoTree {
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

fn tree_false() -> ErgoTree {
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

fn tree_hash(tree: &ErgoTree) -> Digest32 {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, tree).unwrap();
    blake2b256(&w.result())
}

/// Compute the template hash for an `ErgoTree` using the same code path
/// the apply loop uses for outputs (`template_hash_from_bytes` on the
/// serialized tree). Both fixture trees in this test serialize to a
/// parseable template, so this returns `Some` for both.
fn template_hash(tree: &ErgoTree) -> Digest32 {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, tree).unwrap();
    Digest32::from_bytes(template_hash_from_bytes(&w.result()).unwrap())
}

fn candidate(value: u64, tree: ErgoTree, height: u32, tokens: Vec<Token>) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(value, tree, height, tokens, AdditionalRegisters::empty()).unwrap()
}

fn fake_input(seed: u8) -> Input {
    Input {
        box_id: Digest32::from_bytes([seed; 32]),
        spending_proof: SpendingProof::new(vec![seed; 4], ContextExtension::empty()).unwrap(),
    }
}

fn spend_input(box_id: Digest32) -> Input {
    Input {
        box_id,
        spending_proof: SpendingProof::new(vec![0x01, 0x02], ContextExtension::empty()).unwrap(),
    }
}

fn sealed_box_id(tx: &Transaction, idx: u16) -> Digest32 {
    let tx_id = transaction_id(tx).unwrap();
    ErgoBox {
        candidate: tx.output_candidates[idx as usize].clone(),
        transaction_id: tx_id,
        index: idx,
    }
    .box_id()
    .unwrap()
}

/// Snapshot of every observable post-apply surface for a given
/// `IndexerStore`, scoped to the box ids and tree hashes touched by the
/// fixture. Equality between two snapshots is the equivalence relation
/// the resume contract must satisfy.
#[derive(Debug, PartialEq)]
struct StateSnapshot {
    meta: IndexerMeta,
    undo_per_height: Vec<(u64, Option<UndoEntry>)>,
    boxes: Vec<(Digest32, Option<IndexedErgoBox>)>,
    /// `NUMERIC_BOX[global_box_index] -> box_id` — backs `/box/byIndex`
    /// reads via `IndexerHandle::box_by_global_index` (handle.rs:184).
    /// Written in the same apply txn at apply.rs:373.
    numeric_boxes: Vec<(u64, Option<Digest32>)>,
    txs: Vec<(Digest32, Option<IndexedErgoTransaction>)>,
    /// `NUMERIC_TX[global_tx_index] -> tx_id` — backs `/transaction/byIndex`
    /// via `IndexerHandle::tx_by_global_index` (handle.rs:226). Written
    /// in the same apply txn at apply.rs:542.
    numeric_txs: Vec<(u64, Option<Digest32>)>,
    /// `IndexedAddress` parent — pins the persisted balance (nano_ergs +
    /// per-token bundle), which the segment-entry vectors don't expose.
    addresses: Vec<(Digest32, Option<IndexedAddress>)>,
    address_box_entries: Vec<(Digest32, Option<Vec<i64>>)>,
    address_tx_entries: Vec<(Digest32, Option<Vec<i64>>)>,
    /// `IndexedTemplate` parent + concatenated box-segment entries —
    /// independent surface from addresses (Scala explorers diff template
    /// records byte-for-byte).
    templates: Vec<(Digest32, Option<IndexedTemplate>)>,
    template_box_entries: Vec<(Digest32, Option<Vec<i64>>)>,
    /// `IndexedToken` parent + concatenated box-segment entries — the
    /// only place EIP-4 mint metadata (creating_box_id, emission_amount,
    /// name, description, decimals) is persisted.
    tokens: Vec<(Digest32, Option<IndexedToken>)>,
    token_box_entries: Vec<(Digest32, Option<Vec<i64>>)>,
    storage_rent_entries: Vec<(u32, i64, ergo_indexer::BoxId, u64, i32)>,
}

#[allow(clippy::too_many_arguments)]
fn snapshot(
    store: &IndexerStore,
    heights: &[u64],
    box_ids: &[Digest32],
    global_box_indices: &[u64],
    tx_ids: &[Digest32],
    global_tx_indices: &[u64],
    tree_hashes: &[Digest32],
    template_hashes: &[Digest32],
    token_ids: &[Digest32],
) -> StateSnapshot {
    StateSnapshot {
        meta: store.read_meta().unwrap(),
        undo_per_height: heights
            .iter()
            .map(|&h| (h, store.read_undo(h).unwrap()))
            .collect(),
        boxes: box_ids
            .iter()
            .map(|id| (*id, store.read_box(id).unwrap()))
            .collect(),
        numeric_boxes: global_box_indices
            .iter()
            .map(|&n| (n, store.read_numeric_box(n).unwrap()))
            .collect(),
        txs: tx_ids
            .iter()
            .map(|id| (*id, store.read_tx(id).unwrap()))
            .collect(),
        numeric_txs: global_tx_indices
            .iter()
            .map(|&n| (n, store.read_numeric_tx(n).unwrap()))
            .collect(),
        addresses: tree_hashes
            .iter()
            .map(|h| (*h, store.read_address(h).unwrap()))
            .collect(),
        address_box_entries: tree_hashes
            .iter()
            .map(|h| (*h, store.read_address_box_entries(h).unwrap()))
            .collect(),
        address_tx_entries: tree_hashes
            .iter()
            .map(|h| (*h, store.read_address_tx_entries(h).unwrap()))
            .collect(),
        templates: template_hashes
            .iter()
            .map(|h| (*h, store.read_template(h).unwrap()))
            .collect(),
        template_box_entries: template_hashes
            .iter()
            .map(|h| (*h, store.read_template_box_entries(h).unwrap()))
            .collect(),
        tokens: token_ids
            .iter()
            .map(|id| (*id, store.read_token(id).unwrap()))
            .collect(),
        token_box_entries: token_ids
            .iter()
            .map(|id| (*id, store.read_token_box_entries(id).unwrap()))
            .collect(),
        storage_rent_entries: store.read_storage_rent_entries().unwrap(),
    }
}

// ----- happy path -----

/// Apply a 2-block fixture two ways:
///   - Path A: single uninterrupted session.
///   - Path B: apply block 1, drop the store (releases the redb file
///     handle), reopen at the same path, apply block 2.
///
/// Path B is the deterministic test-time analogue of "process exited
/// after committing block 1, restarted, resumed at height 2". Every
/// observable surface flushed inside the apply txn must match Path A
/// byte-for-byte: meta, undo, box rows + NUMERIC_BOX, tx rows +
/// NUMERIC_TX, address parent + balance + segments, template parent +
/// segments, token parent + segments, storage_rent rows.
///
/// Under `Durability::Eventual` (apply.rs:152-159), the redb file is
/// closed cleanly on `Drop`, so all committed transactions are visible
/// on reopen. The contract this pins is unchanged from before the
/// durability flip; the test is a regression guard for the now
/// load-bearing recovery path.
#[test]
fn close_reopen_continue_matches_uninterrupted_apply() {
    // Two trees so we exercise multiple addresses/templates.
    let t_a = tree_true();
    let t_b = tree_false();
    let hash_a = tree_hash(&t_a);
    let hash_b = tree_hash(&t_b);

    // Genesis: two-tx block. tx0 mints a token to address A; tx1
    // sends to address B with 2 outputs. Diverse enough to hit
    // boxes, txs, addresses (A + B), storage_rent (3 outputs), and
    // tokens.
    let mint_seed = 0x42;
    let mint_token_id: Digest32 = Digest32::from_bytes([mint_seed; 32]);
    let mint_input_box: Digest32 = Digest32::from_bytes([mint_seed; 32]);

    let g_tx0 = Transaction {
        inputs: vec![Input {
            box_id: mint_input_box,
            spending_proof: SpendingProof::new(vec![0x10], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(
            500_000,
            t_a.clone(),
            1,
            vec![Token {
                token_id: mint_token_id,
                amount: 1000,
            }],
        )],
    };
    let g_tx1 = Transaction {
        inputs: vec![fake_input(0x21)],
        data_inputs: vec![],
        output_candidates: vec![
            candidate(750_000, t_b.clone(), 1, vec![]),
            candidate(250_000, t_b.clone(), 1, vec![]),
        ],
    };
    let g_block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: &[g_tx0.clone(), g_tx1.clone()],
    };

    // h=2 spends one of the genesis outputs and creates a new output
    // back to address A. This forces a sign-flip on A's box-segment
    // entry plus a balance edit, exactly the surface most likely to
    // diverge if the resume path skips a flush.
    let spent_box = sealed_box_id(&g_tx0, 0);
    let h2_tx = Transaction {
        inputs: vec![spend_input(spent_box)],
        data_inputs: vec![],
        output_candidates: vec![candidate(400_000, t_a.clone(), 2, vec![])],
    };
    let h2_block = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&h2_tx),
    };

    // Box ids we expect to be readable after the run.
    let box_ids = vec![
        sealed_box_id(&g_tx0, 0),
        sealed_box_id(&g_tx1, 0),
        sealed_box_id(&g_tx1, 1),
        sealed_box_id(&h2_tx, 0),
    ];
    let tx_ids = vec![
        *transaction_id(&g_tx0).unwrap().as_digest(),
        *transaction_id(&g_tx1).unwrap().as_digest(),
        *transaction_id(&h2_tx).unwrap().as_digest(),
    ];
    let tree_hashes = vec![hash_a, hash_b];
    let template_hashes = vec![template_hash(&t_a), template_hash(&t_b)];
    let token_ids = vec![mint_token_id];
    let heights = vec![1u64, 2u64];
    // Apply assigns global_box_index per output in document order:
    //   g_tx0[0]=0, g_tx1[0]=1, g_tx1[1]=2, h2_tx[0]=3.
    // global_tx_index per tx in block order:
    //   g_tx0=0, g_tx1=1, h2_tx=2.
    // Plus index 4 / 3 (out-of-range) to assert `None` is consistent.
    let global_box_indices = vec![0u64, 1, 2, 3, 4];
    let global_tx_indices = vec![0u64, 1, 2, 3];

    // Path A: uninterrupted.
    let tmp_a = TempDir::new().unwrap();
    let path_a = tmp_a.path().join("indexer.redb");
    let snap_a = {
        let (store, _) = IndexerStore::open(&path_a).unwrap();
        let m1 = apply_block(&store, &IndexerMeta::empty(), &g_block).unwrap();
        let _m2 = apply_block(&store, &m1, &h2_block).unwrap();
        snapshot(
            &store,
            &heights,
            &box_ids,
            &global_box_indices,
            &tx_ids,
            &global_tx_indices,
            &tree_hashes,
            &template_hashes,
            &token_ids,
        )
    };

    // Path B: apply h=1, drop, reopen, apply h=2.
    let tmp_b = TempDir::new().unwrap();
    let path_b = tmp_b.path().join("indexer.redb");
    let m1_b = {
        let (store, _) = IndexerStore::open(&path_b).unwrap();
        apply_block(&store, &IndexerMeta::empty(), &g_block).unwrap()
        // store dropped here — releases the redb file handle.
    };
    let snap_b = {
        let (store, _) = IndexerStore::open(&path_b).unwrap();
        // Persisted meta on reopen must match the meta returned at h=1.
        assert_eq!(store.read_meta().unwrap(), m1_b);
        apply_block(&store, &m1_b, &h2_block).unwrap();
        snapshot(
            &store,
            &heights,
            &box_ids,
            &global_box_indices,
            &tx_ids,
            &global_tx_indices,
            &tree_hashes,
            &template_hashes,
            &token_ids,
        )
    };

    assert_eq!(
        snap_a, snap_b,
        "post-resume state must equal single-session state across meta, undo, boxes (rows + NUMERIC_BOX), txs (rows + NUMERIC_TX), addresses (parent + balance + segments), templates (parent + segments), tokens (parent + segments), and storage_rent",
    );
}

/// Snapshot of every spill-backed read surface — the `SEGMENTS` redb
/// table. Reaches them three ways:
///   1. parent record (`segment_count` field) via `read_address`,
///      `read_template`, `read_token`,
///   2. concatenated entries via `read_*_box_entries` (which walks every
///      spill row plus the head),
///   3. raw spill rows via `read_spill_segment(box_segment_id(parent, 0))`.
///
/// All three must agree across reopen — diverging would mean either the
/// parent's spill counter survived but the row didn't, or vice versa.
#[derive(Debug, PartialEq)]
struct SpillSnapshot {
    address: Option<IndexedAddress>,
    address_box_entries: Option<Vec<i64>>,
    address_box_spill_0: Option<Segment>,
    template: Option<IndexedTemplate>,
    template_box_entries: Option<Vec<i64>>,
    template_box_spill_0: Option<Segment>,
    token: Option<IndexedToken>,
    token_box_entries: Option<Vec<i64>>,
    token_box_spill_0: Option<Segment>,
    storage_rent_count: usize,
}

fn spill_snapshot(
    store: &IndexerStore,
    addr_hash: &Digest32,
    template_hash: &Digest32,
    token_id: &Digest32,
) -> SpillSnapshot {
    SpillSnapshot {
        address: store.read_address(addr_hash).unwrap(),
        address_box_entries: store.read_address_box_entries(addr_hash).unwrap(),
        address_box_spill_0: store
            .read_spill_segment(&box_segment_id(addr_hash, 0))
            .unwrap(),
        template: store.read_template(template_hash).unwrap(),
        template_box_entries: store.read_template_box_entries(template_hash).unwrap(),
        template_box_spill_0: store
            .read_spill_segment(&box_segment_id(template_hash, 0))
            .unwrap(),
        token: store.read_token(token_id).unwrap(),
        token_box_entries: store.read_token_box_entries(token_id).unwrap(),
        // Token spills key under the derived `token_unique_id` (the same
        // value the apply path uses at apply.rs:324 to build the parent
        // id for the segment write).
        token_box_spill_0: store
            .read_spill_segment(&box_segment_id(&token_unique_id(token_id), 0))
            .unwrap(),
        storage_rent_count: store.read_storage_rent_entries().unwrap().len(),
    }
}

/// Forces three spill-backed read surfaces to be exercised across a
/// reopen — the gap Codex flagged on the third re-review. Builds a
/// genesis block (height=1, so spend logic is skipped) with one tx
/// emitting 513 outputs, all of which:
///   - go to the same address (forces address-box spill at 512 entries),
///   - use the same template-parseable tree (forces template-box spill),
///   - carry the same minted token (forces token-box spill).
///
/// Path A applies in a single session; Path B applies, drops the store
/// (releases the redb file handle), reopens at the same path, and
/// re-snapshots. Every spill-backed surface — parent `segment_count`,
/// concatenated entry vector, raw `SEGMENTS[box_segment_id(parent, 0)]`
/// row — must match Path A.
///
/// Address tx-segment spill is NOT exercised here (1 tx → 1 entry, well
/// below 512). It shares the `SEGMENTS` redb table and the
/// `flush_staged_spills` code path with the box-segment spills above
/// (segment_buffer.rs), so the close/reopen contract for tx-segment
/// spills is implied — the apply transaction does not distinguish row
/// types when committing under `Durability::Eventual`.
#[test]
fn close_reopen_preserves_spill_segments() {
    use ergo_indexer::segment::SEGMENT_THRESHOLD;
    assert_eq!(
        SEGMENT_THRESHOLD, 512,
        "test fixture sized for SEGMENT_THRESHOLD=512; bump output count if this changes",
    );

    let tree = tree_true();
    let addr_hash = tree_hash(&tree);
    let template_h = template_hash(&tree);

    // Mint condition: token_id == tx.inputs[0].box_id AND token_id is
    // not in input_tokens. At height=1 the spend loop is skipped, so
    // input_tokens stays empty and the mint fires for every output
    // emitting `mint_token_id`.
    let mint_seed = 0x55;
    let mint_token_id: Digest32 = Digest32::from_bytes([mint_seed; 32]);
    let mint_input_box: Digest32 = Digest32::from_bytes([mint_seed; 32]);

    // 513 outputs — exactly one over SEGMENT_THRESHOLD so each
    // segment lands one spill row plus a head of length 1.
    let n_outputs: usize = SEGMENT_THRESHOLD + 1;
    let outputs: Vec<ErgoBoxCandidate> = (0..n_outputs)
        .map(|i| {
            // Distinct values so each output is byte-distinct (avoids
            // any chance of incidental redb dedup paths).
            let value = 100_000u64 + i as u64;
            ErgoBoxCandidate::new(
                value,
                tree.clone(),
                1,
                vec![Token {
                    token_id: mint_token_id,
                    amount: 1,
                }],
                AdditionalRegisters::empty(),
            )
            .unwrap()
        })
        .collect();
    let tx = Transaction {
        inputs: vec![Input {
            box_id: mint_input_box,
            spending_proof: SpendingProof::new(vec![0xAA], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: outputs,
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0xEE; 32]),
        transactions: std::slice::from_ref(&tx),
    };

    // Path A: uninterrupted.
    let tmp_a = TempDir::new().unwrap();
    let path_a = tmp_a.path().join("indexer.redb");
    let snap_a = {
        let (store, _) = IndexerStore::open(&path_a).unwrap();
        let _ = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
        spill_snapshot(&store, &addr_hash, &template_h, &mint_token_id)
    };

    // Path B: apply, drop, reopen, snapshot (no further apply needed —
    // the spill rows must be readable on reopen *as written*).
    let tmp_b = TempDir::new().unwrap();
    let path_b = tmp_b.path().join("indexer.redb");
    {
        let (store, _) = IndexerStore::open(&path_b).unwrap();
        apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
    }
    let snap_b = {
        let (store, _) = IndexerStore::open(&path_b).unwrap();
        spill_snapshot(&store, &addr_hash, &template_h, &mint_token_id)
    };

    // Sanity: the fixture actually crossed the spill threshold —
    // otherwise the test would silently devolve into the small-fixture
    // case the prior test already covers.
    assert!(
        snap_a.address_box_spill_0.is_some(),
        "address spill_0 must exist — fixture failed to cross SEGMENT_THRESHOLD",
    );
    assert!(snap_a.template_box_spill_0.is_some());
    assert!(snap_a.token_box_spill_0.is_some());
    assert_eq!(snap_a.storage_rent_count, n_outputs);

    assert_eq!(
        snap_a, snap_b,
        "post-reopen state must equal single-session state across spill-backed reads (parent segment_count, entry concatenation, raw SEGMENTS row)",
    );
}
