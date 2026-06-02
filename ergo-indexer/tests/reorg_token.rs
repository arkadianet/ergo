//! Reorg equivalence tests for forks containing token mints.
//!
//! Three reorg shapes are pinned, each one verifying that the indexer
//! ends up byte-for-byte identical to a fresh DB that only ever saw
//! fork-B:
//!   - **first mint**: fork-A creates a new `IndexedToken` record;
//!     reorg must delete the record (not zero it) so a subsequent
//!     `read_token` returns `None`, matching fresh-DB state.
//!   - **multi-output mint**: fork-A's mint tx spreads the new token
//!     across two outputs (so `emission_amount` accumulates and the
//!     token-segment grows by two entries in a single block); reorg
//!     must unwind both segment entries and the parent record.
//!   - **mint then spend**: fork-A is two blocks — mint in block 1,
//!     transfer (which carries the same token id forward, this time
//!     as a plain transfer not a mint) in block 2. Reorg unwinds
//!     both blocks: the segment must be empty, the record gone.
//!
//! There is also a fourth case — the pre-apply-vs-post-rollback
//! topology-equality invariant for the token table — pinning that
//! `apply_block` then `rollback_one_block` for a mint-bearing block
//! leaves the persisted state byte-for-byte identical to the snapshot
//! taken before the apply (so rollback is a true inverse, not just
//! "looks correct after follow-up writes").
//!
//! All forks use the same `parseable_tree_true` candidate tree, so the
//! template hash and address tree-hash are shared across both forks
//! and across the test/reference DBs. That keeps the snapshot diff
//! sensitive to *only* the token-side delta, not unrelated template
//! / address churn.

use ergo_primitives::digest::Digest32;
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

use ergo_indexer::{
    apply_block, rollback_one_block, BoxId, HeaderId, IndexerBlock, IndexerMeta, IndexerStore,
    TokenId, TxId, UndoEntry,
};
use ergo_indexer_types::{IndexedErgoBox, IndexedErgoTransaction};

// ---------- shared fixtures ---------------------------------------------

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

fn tree_bytes(tree: &ErgoTree) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, tree).unwrap();
    w.result()
}

fn template_hash_of(tree: &ErgoTree) -> Digest32 {
    let arr = template_hash_from_bytes(&tree_bytes(tree)).expect("tree must be template-parseable");
    Digest32::from_bytes(arr)
}

fn tree_hash_of(tree: &ErgoTree) -> Digest32 {
    ergo_primitives::digest::blake2b256(&tree_bytes(tree))
}

fn candidate(value: u64, height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        parseable_tree_true(),
        height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn candidate_with_tokens(value: u64, height: u32, tokens: Vec<Token>) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        parseable_tree_true(),
        height,
        tokens,
        AdditionalRegisters::empty(),
    )
    .unwrap()
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

/// Build a spending proof whose body bytes embed `tag` + `index`. The
/// indexer doesn't verify proofs, but distinct proof bytes give every
/// fork a distinct tx serialization, which keeps tx_ids and downstream
/// box_ids different across fork-A and fork-B.
fn proof(tag: u8, index: u8) -> SpendingProof {
    SpendingProof::new(vec![tag, index, 0xCA, 0xFE], ContextExtension::empty()).unwrap()
}

fn input_spending(box_id: Digest32, tag: u8, index: u8) -> Input {
    Input {
        box_id,
        spending_proof: proof(tag, index),
    }
}

// ---------- chain block harness -----------------------------------------

struct ChainBlock {
    height: i32,
    header_id: HeaderId,
    txs: Vec<Transaction>,
}

impl ChainBlock {
    fn as_indexer(&self) -> IndexerBlock<'_> {
        IndexerBlock {
            height: self.height,
            header_id: self.header_id,
            transactions: &self.txs,
        }
    }
}

fn header_id_for(tag: u8, height: i32) -> HeaderId {
    let mut h = [tag; 32];
    h[0] = tag;
    h[1] = height as u8;
    Digest32::from_bytes(h)
}

/// Genesis: dummy input, single funding output. Returns the block plus
/// the sealed box id that downstream forks will spend.
fn build_genesis() -> (ChainBlock, BoxId) {
    let tx = Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes([0xFF; 32]),
            spending_proof: proof(0xFE, 0),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000_000, 1)],
    };
    let funding_id = sealed_box_id(&tx, 0);
    (
        ChainBlock {
            height: 1,
            header_id: header_id_for(0x01, 1),
            txs: vec![tx],
        },
        funding_id,
    )
}

/// Plain (non-mint) block: spend `parent_output`, emit one new funding
/// child. Used for both fork-B and as the "tail" of a multi-block
/// fork-A in the mint-then-spend variant.
fn build_plain_block(tag: u8, height: i32, parent_output: BoxId) -> (ChainBlock, BoxId) {
    let tx = Transaction {
        inputs: vec![input_spending(parent_output, tag, height as u8)],
        data_inputs: vec![],
        output_candidates: vec![candidate(500_000_000, height as u32)],
    };
    let next = sealed_box_id(&tx, 0);
    (
        ChainBlock {
            height,
            header_id: header_id_for(tag, height),
            txs: vec![tx],
        },
        next,
    )
}

/// Mint block (single output): spend `parent_output` and emit one
/// output carrying the new token. EIP-4 contract requires
/// `token_id == tx.inputs[0].box_id`, so the minted id is `parent_output`.
/// Returns the block, the next funding output for chaining, and the
/// minted token id.
fn build_mint_block_single(
    tag: u8,
    height: i32,
    parent_output: BoxId,
    amount: u64,
) -> (ChainBlock, BoxId, TokenId) {
    let token_id: TokenId = parent_output;
    let tx = Transaction {
        inputs: vec![input_spending(parent_output, tag, height as u8)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            500_000_000,
            height as u32,
            vec![Token { token_id, amount }],
        )],
    };
    let next = sealed_box_id(&tx, 0);
    (
        ChainBlock {
            height,
            header_id: header_id_for(tag, height),
            txs: vec![tx],
        },
        next,
        token_id,
    )
}

/// Mint block (multi output): single tx spreads the new token across
/// two outputs. The token-segment grows by 2 in this single block, and
/// `emission_amount` accumulates `amount_a + amount_b`.
fn build_mint_block_multi_output(
    tag: u8,
    height: i32,
    parent_output: BoxId,
    amount_a: u64,
    amount_b: u64,
) -> (ChainBlock, BoxId, TokenId) {
    let token_id: TokenId = parent_output;
    let tx = Transaction {
        inputs: vec![input_spending(parent_output, tag, height as u8)],
        data_inputs: vec![],
        output_candidates: vec![
            candidate_with_tokens(
                400_000_000,
                height as u32,
                vec![Token {
                    token_id,
                    amount: amount_a,
                }],
            ),
            candidate_with_tokens(
                400_000_000,
                height as u32,
                vec![Token {
                    token_id,
                    amount: amount_b,
                }],
            ),
        ],
    };
    // Chain off output 1 — output 0 is reserved for a follow-up spend
    // in the mint-then-spend variant.
    let next = sealed_box_id(&tx, 1);
    (
        ChainBlock {
            height,
            header_id: header_id_for(tag, height),
            txs: vec![tx],
        },
        next,
        token_id,
    )
}

/// Plain transfer block that spends a token-bearing input and forwards
/// the same token to a new owner. Because `token_id ∈ inputTokens`,
/// `is_mint` is false on the new output — no IndexedToken is created
/// or amended, but the segment gets a +entry (new owner) plus a
/// flipped −entry (spent input). Used in the mint-then-spend variant.
fn build_token_transfer_block(
    tag: u8,
    height: i32,
    parent_output: BoxId,
    token_id: TokenId,
    amount: u64,
) -> (ChainBlock, BoxId) {
    let tx = Transaction {
        inputs: vec![input_spending(parent_output, tag, height as u8)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            300_000_000,
            height as u32,
            vec![Token { token_id, amount }],
        )],
    };
    let next = sealed_box_id(&tx, 0);
    (
        ChainBlock {
            height,
            header_id: header_id_for(tag, height),
            txs: vec![tx],
        },
        next,
    )
}

// ---------- snapshot ----------------------------------------------------

/// Captures every reachable indexer row the reorg tests care about.
/// Two snapshots being `==` means the underlying redb tables are
/// byte-for-byte identical for boxes / txs / numeric / meta / undo
/// plus the per-template, per-address, and per-token
/// surfaces (the P3 surface).
///
/// `tracked_token_ids` and `tracked_template_hashes` / `tracked_tree_hashes`
/// are read in fixed input order so equality is order-stable. Reads
/// returning `None` are recorded as `None` (so the snapshot can compare
/// "record exists in DB-A, absent in DB-B" cleanly — the post-reorg
/// equivalence we are pinning).
#[derive(Debug, PartialEq)]
struct IndexerSnapshot {
    meta: IndexerMeta,
    num_boxes: Vec<BoxId>,
    num_txs: Vec<TxId>,
    boxes: Vec<IndexedErgoBox>,
    txs: Vec<IndexedErgoTransaction>,
    undos: Vec<(u64, UndoEntry)>,
    addresses: Vec<(Digest32, Option<AddressRecord>)>,
    templates: Vec<(Digest32, Option<TemplateRecord>)>,
    tokens: Vec<(TokenId, Option<TokenRecord>)>,
}

#[derive(Debug, PartialEq)]
struct AddressRecord {
    box_entries: Option<Vec<i64>>,
    tx_entries: Option<Vec<i64>>,
}

#[derive(Debug, PartialEq)]
struct TemplateRecord {
    box_entries: Option<Vec<i64>>,
}

#[derive(Debug, PartialEq)]
struct TokenRecord {
    name: Option<String>,
    description: Option<String>,
    decimals: Option<i32>,
    emission_amount: Option<u64>,
    creating_box_id: Option<BoxId>,
    box_entries: Option<Vec<i64>>,
}

fn snapshot(
    store: &IndexerStore,
    tracked_tree_hashes: &[Digest32],
    tracked_template_hashes: &[Digest32],
    tracked_token_ids: &[TokenId],
) -> IndexerSnapshot {
    let meta = store.read_meta().unwrap();

    let mut num_boxes = Vec::with_capacity(meta.global_box_index as usize);
    let mut boxes = Vec::with_capacity(meta.global_box_index as usize);
    for n in 0..meta.global_box_index {
        let id = store
            .read_numeric_box(n)
            .unwrap()
            .unwrap_or_else(|| panic!("NUMERIC_BOX[{n}] missing"));
        let row = store
            .read_box(&id)
            .unwrap()
            .unwrap_or_else(|| panic!("INDEXED_BOX missing for NUMERIC_BOX[{n}]"));
        num_boxes.push(id);
        boxes.push(row);
    }

    let mut num_txs = Vec::with_capacity(meta.global_tx_index as usize);
    let mut txs = Vec::with_capacity(meta.global_tx_index as usize);
    for n in 0..meta.global_tx_index {
        let id = store
            .read_numeric_tx(n)
            .unwrap()
            .unwrap_or_else(|| panic!("NUMERIC_TX[{n}] missing"));
        let row = store
            .read_tx(&id)
            .unwrap()
            .unwrap_or_else(|| panic!("INDEXED_TX missing for NUMERIC_TX[{n}]"));
        num_txs.push(id);
        txs.push(row);
    }

    let mut undos = Vec::new();
    for h in 1..=meta.indexed_height {
        if let Some(u) = store.read_undo(h).unwrap() {
            undos.push((h, u));
        }
    }

    let addresses = tracked_tree_hashes
        .iter()
        .map(|th| {
            let rec = store.read_address(th).unwrap().map(|_| AddressRecord {
                box_entries: store.read_address_box_entries(th).unwrap(),
                tx_entries: store.read_address_tx_entries(th).unwrap(),
            });
            (*th, rec)
        })
        .collect();

    let templates = tracked_template_hashes
        .iter()
        .map(|th| {
            let rec = store.read_template(th).unwrap().map(|_| TemplateRecord {
                box_entries: store.read_template_box_entries(th).unwrap(),
            });
            (*th, rec)
        })
        .collect();

    let tokens = tracked_token_ids
        .iter()
        .map(|tid| {
            let rec = store.read_token(tid).unwrap().map(|t| TokenRecord {
                name: t.name.clone(),
                description: t.description.clone(),
                decimals: t.decimals,
                emission_amount: t.emission_amount,
                creating_box_id: t.creating_box_id,
                box_entries: store.read_token_box_entries(tid).unwrap(),
            });
            (*tid, rec)
        })
        .collect();

    IndexerSnapshot {
        meta,
        num_boxes,
        num_txs,
        boxes,
        txs,
        undos,
        addresses,
        templates,
        tokens,
    }
}

// ---------- chain plumbing ----------------------------------------------

fn apply_chain(
    store: &IndexerStore,
    blocks: &[ChainBlock],
    start_meta: &IndexerMeta,
) -> IndexerMeta {
    let mut meta = start_meta.clone();
    for block in blocks {
        meta = apply_block(store, &meta, &block.as_indexer()).unwrap();
    }
    meta
}

fn rollback_chain(
    store: &IndexerStore,
    blocks: &[ChainBlock],
    top_meta: &IndexerMeta,
) -> IndexerMeta {
    let mut meta = top_meta.clone();
    for block in blocks.iter().rev() {
        meta = rollback_one_block(store, &meta, &block.as_indexer()).unwrap();
    }
    meta
}

// ---------- tests -------------------------------------------------------

#[test]
fn reorg_first_mint_yields_state_identical_to_fresh_fork_b() {
    // fork-A creates a brand-new IndexedToken; fork-B doesn't touch it.
    // After A → rollback → B, the post-state must be byte-for-byte
    // identical to a fresh DB that only ever saw genesis + fork-B —
    // including the token record being absent (None), not present-with-
    // zeroed-fields.
    let (genesis, funding) = build_genesis();

    let (a_block, _, token_id) = build_mint_block_single(0xAA, 2, funding, 21_000_000);
    let fork_a = vec![a_block];

    let (b_block, _) = build_plain_block(0xBB, 2, funding);
    let fork_b = vec![b_block];

    let tracked_tree = vec![tree_hash_of(&parseable_tree_true())];
    let tracked_template = vec![template_hash_of(&parseable_tree_true())];
    let tracked_tokens = vec![token_id];

    // Test DB: walks A, rolls back A, applies B.
    let (store, _tmp) = open_store();
    let m_g = apply_chain(
        &store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let m_a = apply_chain(&store, &fork_a, &m_g);
    // After fork-A, the token must exist.
    assert!(
        store.read_token(&token_id).unwrap().is_some(),
        "fork-A must have created the IndexedToken record"
    );
    let m_back = rollback_chain(&store, &fork_a, &m_a);
    assert_eq!(m_back, m_g);
    assert!(
        store.read_token(&token_id).unwrap().is_none(),
        "rollback of mint block must DELETE the token record, not zero it"
    );
    let m_b = apply_chain(&store, &fork_b, &m_back);
    let snap_via_reorg = snapshot(&store, &tracked_tree, &tracked_template, &tracked_tokens);

    // Reference DB: only ever sees genesis + fork-B.
    let (ref_store, _ref_tmp) = open_store();
    let r_g = apply_chain(
        &ref_store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let r_b = apply_chain(&ref_store, &fork_b, &r_g);
    assert_eq!(m_b, r_b);
    let snap_fresh = snapshot(
        &ref_store,
        &tracked_tree,
        &tracked_template,
        &tracked_tokens,
    );

    assert_eq!(
        snap_via_reorg, snap_fresh,
        "post-reorg state must equal fresh fork-B state byte-for-byte"
    );
}

#[test]
fn reorg_multi_output_mint_yields_state_identical_to_fresh_fork_b() {
    // fork-A's mint tx spreads token T across two outputs in a single
    // block. The token-segment grows by two entries and emission_amount
    // accumulates. Reorg must unwind both segment entries AND the
    // parent record.
    let (genesis, funding) = build_genesis();

    let (a_block, _, token_id) = build_mint_block_multi_output(0xAA, 2, funding, 7_000, 13_000);
    let fork_a = vec![a_block];

    let (b_block, _) = build_plain_block(0xBB, 2, funding);
    let fork_b = vec![b_block];

    let tracked_tree = vec![tree_hash_of(&parseable_tree_true())];
    let tracked_template = vec![template_hash_of(&parseable_tree_true())];
    let tracked_tokens = vec![token_id];

    let (store, _tmp) = open_store();
    let m_g = apply_chain(
        &store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let m_a = apply_chain(&store, &fork_a, &m_g);
    // Confirm the multi-output mint actually accumulated and the
    // segment has two entries before we roll it back.
    let rec = store.read_token(&token_id).unwrap().unwrap();
    assert_eq!(
        rec.emission_amount,
        Some(20_000),
        "emission_amount must accumulate across multi-output mint"
    );
    let entries = store.read_token_box_entries(&token_id).unwrap().unwrap();
    assert_eq!(
        entries.len(),
        2,
        "two outputs minted T → segment must have two entries"
    );
    let m_back = rollback_chain(&store, &fork_a, &m_a);
    assert_eq!(m_back, m_g);
    let m_b = apply_chain(&store, &fork_b, &m_back);
    let snap_via_reorg = snapshot(&store, &tracked_tree, &tracked_template, &tracked_tokens);

    let (ref_store, _ref_tmp) = open_store();
    let r_g = apply_chain(
        &ref_store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let r_b = apply_chain(&ref_store, &fork_b, &r_g);
    assert_eq!(m_b, r_b);
    let snap_fresh = snapshot(
        &ref_store,
        &tracked_tree,
        &tracked_template,
        &tracked_tokens,
    );

    assert_eq!(snap_via_reorg, snap_fresh);
}

#[test]
fn reorg_mint_then_spend_yields_state_identical_to_fresh_fork_b() {
    // fork-A is two blocks: block 1 mints, block 2 spends the mint
    // output and forwards the same token id (a plain transfer, not a
    // mint, since token_id ∈ inputTokens). Rollback walks block 2
    // first, then block 1 — both must invert cleanly.
    let (genesis, funding) = build_genesis();

    let (mint_block, mint_child, token_id) = build_mint_block_single(0xAA, 2, funding, 1_000);
    let (transfer_block, _) = build_token_transfer_block(0xAA, 3, mint_child, token_id, 1_000);
    let fork_a = vec![mint_block, transfer_block];

    let (b_block_2, b_child) = build_plain_block(0xBB, 2, funding);
    let (b_block_3, _) = build_plain_block(0xBB, 3, b_child);
    let fork_b = vec![b_block_2, b_block_3];

    let tracked_tree = vec![tree_hash_of(&parseable_tree_true())];
    let tracked_template = vec![template_hash_of(&parseable_tree_true())];
    let tracked_tokens = vec![token_id];

    let (store, _tmp) = open_store();
    let m_g = apply_chain(
        &store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let m_a = apply_chain(&store, &fork_a, &m_g);
    // After both fork-A blocks the token-segment carries: spent mint
    // output (negative entry) + new transfer output (positive entry).
    let entries = store.read_token_box_entries(&token_id).unwrap().unwrap();
    assert!(
        entries.iter().any(|e| *e < 0),
        "transfer block must sign-flip the mint output entry to negative"
    );
    assert!(
        entries.iter().any(|e| *e > 0),
        "transfer block must append the new output entry"
    );
    let m_back = rollback_chain(&store, &fork_a, &m_a);
    assert_eq!(m_back, m_g);
    assert!(
        store.read_token(&token_id).unwrap().is_none(),
        "rolling back both mint and transfer must leave no token record"
    );
    let m_b = apply_chain(&store, &fork_b, &m_back);
    let snap_via_reorg = snapshot(&store, &tracked_tree, &tracked_template, &tracked_tokens);

    let (ref_store, _ref_tmp) = open_store();
    let r_g = apply_chain(
        &ref_store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let r_b = apply_chain(&ref_store, &fork_b, &r_g);
    assert_eq!(m_b, r_b);
    let snap_fresh = snapshot(
        &ref_store,
        &tracked_tree,
        &tracked_template,
        &tracked_tokens,
    );

    assert_eq!(snap_via_reorg, snap_fresh);
}

#[test]
fn pre_apply_vs_post_rollback_topology_identical_for_mint_block() {
    // Topology-equality invariant for the token-bearing case:
    // snapshot the state at H-1, apply a mint block, roll it back, and
    // diff the live tables against the snapshot. Must be byte-for-byte
    // identical — proves rollback is a true inverse, not just "looks
    // right after follow-up writes". This is the strictest single-block
    // P3 invariant short of the full reorg-equivalence cases above.
    let (genesis, funding) = build_genesis();

    let (mint_block, _, token_id) = build_mint_block_single(0xAA, 2, funding, 21_000_000);

    let tracked_tree = vec![tree_hash_of(&parseable_tree_true())];
    let tracked_template = vec![template_hash_of(&parseable_tree_true())];
    let tracked_tokens = vec![token_id];

    let (store, _tmp) = open_store();
    let m_g = apply_chain(
        &store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let snap_pre = snapshot(&store, &tracked_tree, &tracked_template, &tracked_tokens);

    let m_a = apply_chain(&store, std::slice::from_ref(&mint_block), &m_g);
    let m_back = rollback_chain(&store, std::slice::from_ref(&mint_block), &m_a);
    assert_eq!(m_back, m_g);

    let snap_post = snapshot(&store, &tracked_tree, &tracked_template, &tracked_tokens);
    assert_eq!(
        snap_post, snap_pre,
        "apply→rollback of a mint block must restore byte-for-byte pre-apply state"
    );
}
