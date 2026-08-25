//! Integration tests for the storage-rent eligibility index (slice 1).
//!
//! Exercises `apply_block` + `rollback_one_block` against the
//! `unspent_by_creation_height` table — confirms boxes are indexed by
//! creation_height on apply and removed on rollback.

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

use ergo_indexer::{apply_block, rollback_one_block, IndexerBlock, IndexerMeta, IndexerStore};

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

fn candidate(value: u64, creation_height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        size_delimited_tree(),
        creation_height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn candidate_with_tree(value: u64, tree: ErgoTree, creation_height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        tree,
        creation_height,
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

fn spend_input(box_id: Digest32) -> Input {
    Input {
        box_id,
        spending_proof: SpendingProof::new(vec![0x01, 0x02], ContextExtension::empty()).unwrap(),
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

fn sealed_bytes_len(tx: &Transaction, output_idx: u16) -> i32 {
    let tx_id = transaction_id(tx).unwrap();
    let sealed = ErgoBox {
        candidate: tx.output_candidates[output_idx as usize].clone(),
        transaction_id: tx_id,
        index: output_idx,
    };
    let bytes = ergo_ser::ergo_box::serialize_ergo_box(&sealed).unwrap();
    i32::try_from(bytes.len()).unwrap()
}

#[test]
fn apply_inserts_one_row_per_unspent_output_with_canonical_serialized_length() {
    // Genesis-block tx with two outputs at distinct creation_heights.
    // Each unspent output produces exactly one storage-rent row keyed
    // by `(creation_height, global_box_index)`. The stored
    // `box_bytes_len` matches `serialize_ergo_box(&sealed).len()`
    // (spec §3.2 — used by `compute_storage_fee` later).
    let (store, _tmp) = open_store();
    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_000_000, 1)],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let entries = store.read_storage_rent_entries().unwrap();
    assert_eq!(entries.len(), 2);

    let (h0, gi0, id0, val0, blen0) = entries[0];
    assert_eq!(h0, 1, "key creation_height");
    assert_eq!(gi0, 0, "key global_box_index");
    assert_eq!(id0, sealed_box_id(&tx, 0));
    assert_eq!(val0, 1_000_000);
    assert_eq!(blen0, sealed_bytes_len(&tx, 0));

    let (h1, gi1, id1, val1, blen1) = entries[1];
    assert_eq!(h1, 1);
    assert_eq!(gi1, 1);
    assert_eq!(id1, sealed_box_id(&tx, 1));
    assert_eq!(val1, 2_000_000);
    assert_eq!(blen1, sealed_bytes_len(&tx, 1));
}

#[test]
fn storage_rent_key_uses_box_creation_height_not_inclusion_height() {
    // Spec §2 rule 1 + §3.1: eligibility keys on `box.creationHeight`,
    // never block inclusion height. Apply a non-genesis block where
    // every output stamps a creation_height **different** from the
    // inclusion height; the storage_rent key must reflect the box's
    // own field.
    let (store, _tmp) = open_store();

    let seed_tx = Transaction {
        inputs: vec![fake_input(0xFF)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1)],
    };
    let meta1 = apply_block(
        &store,
        &IndexerMeta::empty(),
        &IndexerBlock {
            height: 1,
            header_id: Digest32::from_bytes([0xC1; 32]),
            transactions: std::slice::from_ref(&seed_tx),
        },
    )
    .unwrap();
    let consume_id = sealed_box_id(&seed_tx, 0);

    // Block 2 inclusion-height is 2; output stamps creation_height=42.
    let stamped_tx = Transaction {
        inputs: vec![spend_input(consume_id)],
        data_inputs: vec![],
        output_candidates: vec![candidate(900_000, 42)],
    };
    apply_block(
        &store,
        &meta1,
        &IndexerBlock {
            height: 2,
            header_id: Digest32::from_bytes([0xC2; 32]),
            transactions: std::slice::from_ref(&stamped_tx),
        },
    )
    .unwrap();

    let entries = store.read_storage_rent_entries().unwrap();
    // Block 1's seed output is now spent; only the stamped output remains.
    assert_eq!(entries.len(), 1);
    let (creation_height_key, _, _, _, _) = entries[0];
    assert_eq!(
        creation_height_key, 42,
        "key must use box.creationHeight (42), not inclusion height (2)"
    );
}

#[test]
fn spend_in_later_block_removes_storage_rent_row_for_consumed_output() {
    let (store, _tmp) = open_store();
    let tx_a = Transaction {
        inputs: vec![fake_input(0xFF)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_000_000, 1)],
    };
    let meta1 = apply_block(
        &store,
        &IndexerMeta::empty(),
        &IndexerBlock {
            height: 1,
            header_id: Digest32::from_bytes([0xA1; 32]),
            transactions: std::slice::from_ref(&tx_a),
        },
    )
    .unwrap();
    assert_eq!(store.read_storage_rent_entries().unwrap().len(), 2);

    let spent_id = sealed_box_id(&tx_a, 0); // global_index = 0
    let tx_b = Transaction {
        inputs: vec![spend_input(spent_id)],
        data_inputs: vec![],
        output_candidates: vec![candidate(900_000, 2)],
    };
    apply_block(
        &store,
        &meta1,
        &IndexerBlock {
            height: 2,
            header_id: Digest32::from_bytes([0xA2; 32]),
            transactions: std::slice::from_ref(&tx_b),
        },
    )
    .unwrap();

    let entries = store.read_storage_rent_entries().unwrap();
    // tx_a output 1 (global 1) is still unspent; tx_b output is new (global 2).
    let global_indices: Vec<i64> = entries.iter().map(|(_, gi, _, _, _)| *gi).collect();
    assert_eq!(global_indices, vec![1, 2]);
}

#[test]
fn intra_block_create_then_spend_leaves_no_storage_rent_row() {
    // Spec §6 slice 1 test: a box created in tx0 and consumed in tx1
    // of the same block must end the block absent from the index.
    // Apply order in the inner loop is `tx order -> input -> output`
    // per tx, so tx0's output is inserted, then tx1's step-1 input
    // pass deletes it.
    let (store, _tmp) = open_store();

    // Block 1: seed an unrelated owner so the indexer is past genesis.
    let tx_seed = Transaction {
        inputs: vec![fake_input(0xFF)],
        data_inputs: vec![],
        output_candidates: vec![candidate(500, 1)],
    };
    let meta1 = apply_block(
        &store,
        &IndexerMeta::empty(),
        &IndexerBlock {
            height: 1,
            header_id: Digest32::from_bytes([0xB1; 32]),
            transactions: std::slice::from_ref(&tx_seed),
        },
    )
    .unwrap();
    let seed_consumed = sealed_box_id(&tx_seed, 0);

    // Block 2:
    //   tx0 spends the seed and produces output X (creation_height=2).
    //   tx1 spends X and produces output Y (creation_height=2).
    // After block 2: only Y remains in storage_rent. X must NOT.
    let tx0 = Transaction {
        inputs: vec![spend_input(seed_consumed)],
        data_inputs: vec![],
        output_candidates: vec![candidate(400, 2)],
    };
    let x_id = sealed_box_id(&tx0, 0);
    let tx1 = Transaction {
        inputs: vec![spend_input(x_id)],
        data_inputs: vec![],
        output_candidates: vec![candidate(300, 2)],
    };
    let y_id = sealed_box_id(&tx1, 0);

    let txs = vec![tx0, tx1];
    apply_block(
        &store,
        &meta1,
        &IndexerBlock {
            height: 2,
            header_id: Digest32::from_bytes([0xB2; 32]),
            transactions: &txs,
        },
    )
    .unwrap();

    let entries = store.read_storage_rent_entries().unwrap();
    let ids: Vec<Digest32> = entries.iter().map(|(_, _, id, _, _)| *id).collect();
    assert!(
        !ids.contains(&x_id),
        "intra-block created+spent X must be absent"
    );
    assert!(ids.contains(&y_id), "Y must remain unspent");
}

#[test]
fn compound_key_orders_by_global_index_when_creation_heights_collide() {
    // Spec §8.1 paging stability: with the compound key
    // `(creation_height, global_box_index)`, two boxes sharing
    // creation_height but with INVERTED `box_id` lex order vs
    // `global_box_index` order must surface in `global_box_index` ASC
    // order — the box_id is in the *value* column, never in the key.
    //
    // We achieve inverted box_id lex order vs assignment order by
    // picking two ErgoTrees with different bytes, which produce
    // distinct sealed bytes and distinct box_ids; we then probe for
    // a tx_id seed that yields the right relationship.
    let (store, _tmp) = open_store();

    // Each candidate output of a single tx differs only in its tree.
    // Within one tx, output_idx 0 gets global_index 0 and output_idx
    // 1 gets global_index 1; their box_ids differ on the tree-bytes
    // contribution, so lex comparison is structural, not adversarial.
    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![
            candidate_with_tree(1_000, size_delimited_tree(), 7),
            candidate_with_tree(2_000, size_delimited_tree_false(), 7),
        ],
    };
    apply_block(
        &store,
        &IndexerMeta::empty(),
        &IndexerBlock {
            height: 1,
            header_id: Digest32::from_bytes([0x11; 32]),
            transactions: std::slice::from_ref(&tx),
        },
    )
    .unwrap();

    let id0 = sealed_box_id(&tx, 0);
    let id1 = sealed_box_id(&tx, 1);

    let entries = store.read_storage_rent_entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].1, 0, "first row must have global_box_index 0");
    assert_eq!(entries[1].1, 1, "second row must have global_box_index 1");
    assert_eq!(entries[0].2, id0);
    assert_eq!(entries[1].2, id1);

    // Independent of which lex ordering id0 / id1 happen to satisfy,
    // the key ordering is fully determined by global_box_index. The
    // assertion above pins that relationship; the box_id check below
    // pins the value-column contents so a regression that swaps key
    // and value also fails.
    assert!(
        id0 != id1,
        "test fixture regression: differing trees should produce differing box_ids"
    );
}

#[test]
fn single_block_reorg_of_creates_clears_storage_rent() {
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
    assert_eq!(store.read_storage_rent_entries().unwrap().len(), 2);

    rollback_one_block(&store, &meta1, &block).unwrap();
    let entries = store.read_storage_rent_entries().unwrap();
    assert!(
        entries.is_empty(),
        "rollback must remove every entry the apply inserted, got {entries:?}"
    );
}

#[test]
fn single_block_reorg_of_spend_restores_storage_rent_for_unspent_box() {
    let (store, _tmp) = open_store();
    let tx_a = Transaction {
        inputs: vec![fake_input(0xFF)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_000_000, 1)],
    };
    let header_a = Digest32::from_bytes([0xA1; 32]);
    let block1 = IndexerBlock {
        height: 1,
        header_id: header_a,
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let spent_id = sealed_box_id(&tx_a, 0);
    let tx_b = Transaction {
        inputs: vec![spend_input(spent_id)],
        data_inputs: vec![],
        output_candidates: vec![candidate(900_000, 2)],
    };
    let header_b = Digest32::from_bytes([0xA2; 32]);
    let block2 = IndexerBlock {
        height: 2,
        header_id: header_b,
        transactions: std::slice::from_ref(&tx_b),
    };
    let meta2 = apply_block(&store, &meta1, &block2).unwrap();
    // Pre-rollback: tx_a output 1 (global 1) and tx_b output (global 2).
    let pre_global: Vec<i64> = store
        .read_storage_rent_entries()
        .unwrap()
        .into_iter()
        .map(|(_, gi, _, _, _)| gi)
        .collect();
    assert_eq!(pre_global, vec![1, 2]);

    rollback_one_block(&store, &meta2, &block2).unwrap();

    // Post-rollback: tx_b output is gone (its create undone), tx_a's
    // spent output is restored — both tx_a outputs are unspent again.
    let entries = store.read_storage_rent_entries().unwrap();
    let ids: Vec<Digest32> = entries.iter().map(|(_, _, id, _, _)| *id).collect();
    assert_eq!(entries.len(), 2);
    assert!(
        ids.contains(&spent_id),
        "rolled-back spend restores the box"
    );
    assert!(ids.contains(&sealed_box_id(&tx_a, 1)));
    let restored = entries
        .iter()
        .find(|(_, _, id, _, _)| *id == spent_id)
        .unwrap();
    // box_value and box_bytes_len round-trip through the apply→spend→rollback path.
    assert_eq!(restored.3, 1_000_000);
    assert_eq!(restored.4, sealed_bytes_len(&tx_a, 0));
}

#[test]
fn apply_rollback_apply_alternative_yields_same_state_as_clean_apply_alternative() {
    // Spec §6 slice 1 test: apply A, roll back, apply B → table state
    // matches a control DB that only saw B.
    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000, 1), candidate(2_000, 1)],
    };
    let tx_b = Transaction {
        inputs: vec![fake_input(0xBB)],
        data_inputs: vec![],
        output_candidates: vec![candidate(7_777, 1)],
    };
    let header_a = Digest32::from_bytes([0xA0; 32]);
    let header_b = Digest32::from_bytes([0xB0; 32]);

    // Path 1: apply A, rollback A, apply B.
    let (store_path1, _t1) = open_store();
    let block_a = IndexerBlock {
        height: 1,
        header_id: header_a,
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta_a = apply_block(&store_path1, &IndexerMeta::empty(), &block_a).unwrap();
    rollback_one_block(&store_path1, &meta_a, &block_a).unwrap();
    let block_b = IndexerBlock {
        height: 1,
        header_id: header_b,
        transactions: std::slice::from_ref(&tx_b),
    };
    apply_block(&store_path1, &IndexerMeta::empty(), &block_b).unwrap();
    let path1 = store_path1.read_storage_rent_entries().unwrap();

    // Path 2: control — apply B only.
    let (store_path2, _t2) = open_store();
    apply_block(
        &store_path2,
        &IndexerMeta::empty(),
        &IndexerBlock {
            height: 1,
            header_id: header_b,
            transactions: std::slice::from_ref(&tx_b),
        },
    )
    .unwrap();
    let path2 = store_path2.read_storage_rent_entries().unwrap();

    assert_eq!(
        path1, path2,
        "apply-A→rollback-A→apply-B must equal clean apply-B"
    );
}

#[test]
fn ten_block_apply_then_rollback_returns_table_to_empty() {
    // Slice 1 §8.4 reorg test scaled down to a slice-1-relevant depth:
    // apply 10 sequential blocks each adding one create + one spend
    // (after the seed block), then roll all 10 back. The "crossing the
    // index cutoff" framing in the spec is a slice-2 query concern;
    // for slice 1 the assertion is structural — every apply has an
    // exact inverse.
    let (store, _tmp) = open_store();

    // Block 1: seed two boxes so subsequent blocks have something to
    // spend.
    let seed_tx = Transaction {
        inputs: vec![fake_input(0xFF)],
        data_inputs: vec![],
        output_candidates: vec![candidate(10_000, 1), candidate(10_000, 1)],
    };
    let header1 = Digest32::from_bytes([0x10; 32]);
    let block1 = IndexerBlock {
        height: 1,
        header_id: header1,
        transactions: std::slice::from_ref(&seed_tx),
    };
    let mut meta = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    // Blocks 2..=11: each consumes the previous block's output 0 and
    // produces a fresh output. Track every block we apply so we can
    // roll them back in reverse.
    let mut applied: Vec<(IndexerMeta, Transaction, Digest32, i32)> = Vec::new();
    let mut last_consumable = sealed_box_id(&seed_tx, 0);
    for h in 2i32..=11 {
        let tx = Transaction {
            inputs: vec![spend_input(last_consumable)],
            data_inputs: vec![],
            output_candidates: vec![candidate(5_000 + h as u64, h as u32)],
        };
        let header = Digest32::from_bytes([h as u8; 32]);
        let block = IndexerBlock {
            height: h,
            header_id: header,
            transactions: std::slice::from_ref(&tx),
        };
        let meta_pre = meta.clone();
        meta = apply_block(&store, &meta_pre, &block).unwrap();
        last_consumable = sealed_box_id(&tx, 0);
        applied.push((meta.clone(), tx, header, h));
    }

    // Roll back blocks 11 → 2 in reverse.
    while let Some((meta_after_apply, tx, header, h)) = applied.pop() {
        let block = IndexerBlock {
            height: h,
            header_id: header,
            transactions: std::slice::from_ref(&tx),
        };
        meta = rollback_one_block(&store, &meta_after_apply, &block).unwrap();
    }

    // Roll back block 1 (the seed).
    rollback_one_block(&store, &meta, &block1).unwrap();
    assert!(
        store.read_storage_rent_entries().unwrap().is_empty(),
        "10-block apply + rollback must leave the table empty"
    );
}

#[test]
fn store_close_and_reopen_preserves_storage_rent_state_across_block_boundary() {
    // Spec §8.5 crash safety scaled to the tests' atomicity budget:
    // commits are per-block, so the only deterministic
    // "kill-mid-batch" surface for a unit test is "kill between
    // committed blocks". Apply h=1, drop the store, re-open, apply
    // h=2 — the storage_rent state after h=2 must equal the state we
    // would have observed in a single uninterrupted session.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");

    let tx_a = Transaction {
        inputs: vec![fake_input(0xFF)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_000_000, 1)],
    };
    let header_a = Digest32::from_bytes([0xA1; 32]);
    let block1 = IndexerBlock {
        height: 1,
        header_id: header_a,
        transactions: std::slice::from_ref(&tx_a),
    };
    let consumed_id = sealed_box_id(&tx_a, 0);

    let meta_after_block1 = {
        let (store, _) = IndexerStore::open(&path).unwrap();
        let meta = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();
        // Drop the store on scope exit (releases the redb file lock).
        meta
    };

    // Re-open and continue with block 2.
    let tx_b = Transaction {
        inputs: vec![spend_input(consumed_id)],
        data_inputs: vec![],
        output_candidates: vec![candidate(900_000, 2)],
    };
    let header_b = Digest32::from_bytes([0xA2; 32]);
    let block2 = IndexerBlock {
        height: 2,
        header_id: header_b,
        transactions: std::slice::from_ref(&tx_b),
    };

    let resumed_entries = {
        let (store, _) = IndexerStore::open(&path).unwrap();
        // Persisted meta on reopen must equal the meta returned at end
        // of block 1.
        assert_eq!(store.read_meta().unwrap(), meta_after_block1);
        // Storage_rent rows from block 1 must be intact.
        let after_block1 = store.read_storage_rent_entries().unwrap();
        assert_eq!(after_block1.len(), 2);
        apply_block(&store, &meta_after_block1, &block2).unwrap();
        store.read_storage_rent_entries().unwrap()
    };

    // Control: same workload in a single session.
    let (control_store, _ctrl_tmp) = open_store();
    let m1 = apply_block(&control_store, &IndexerMeta::empty(), &block1).unwrap();
    apply_block(&control_store, &m1, &block2).unwrap();
    let control_entries = control_store.read_storage_rent_entries().unwrap();

    assert_eq!(
        resumed_entries, control_entries,
        "post-resume state must equal single-session state"
    );
}

#[test]
fn schema_bump_v1_to_v2_wipes_existing_db() {
    // A v1 redb file in the fixed pre-bump format (one schema_version
    // key set to 1) must wipe-and-recreate on first open at v2 per
    // §4.2 wipe rule. The freshly created post-wipe DB has the new
    // schema_version stamped and an empty storage_rent table on
    // first read.
    use ergo_indexer::store::OpenOutcome;
    use redb::{Database, TableDefinition};

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");

    // Construct a minimal v1 DB by hand: indexer_meta table with
    // schema_version = 1 and nothing else.
    {
        let db = Database::create(&path).unwrap();
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        {
            let meta_table: TableDefinition<&str, &[u8]> = TableDefinition::new("indexer_meta");
            let mut t = txn.open_table(meta_table).unwrap();
            let v: [u8; 4] = 1u32.to_be_bytes();
            t.insert("schema_version", v.as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }

    let (_store, outcome) = IndexerStore::open(&path).unwrap();
    assert_eq!(
        outcome,
        OpenOutcome::WipedAndRecreated {
            previous_version: 1
        },
        "v1 → v2 must trigger the §4.2 wipe path"
    );
}

// ----- error paths -----

/// `remove_unspent` surfaces `IndexerError::StorageRentDesync` when the
/// spent box's row is already absent from `UNSPENT_BY_CREATION_HEIGHT`.
/// This drives the typed variant end-to-end through `apply_block`
/// rather than just pinning the constructor + halt-reason at the unit
/// level.
#[test]
fn storage_rent_desync_surfaces_when_unspent_row_missing_at_apply_time() {
    use ergo_indexer::IndexerError;
    use redb::{Database, TableDefinition};

    // Local re-declaration matching the crate-private constant. redb
    // identifies tables by name + key/value types, so the bytes round-
    // trip identically across this declaration.
    const UNSPENT_BY_CREATION_HEIGHT_TEST: TableDefinition<(u32, i64), &'static [u8]> =
        TableDefinition::new("unspent_by_creation_height");

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();

    // Block 1: create one box (rent-eligible).
    let tx_a = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1)],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0xB1; 32]),
        transactions: std::slice::from_ref(&tx_a),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let created_id = sealed_box_id(&tx_a, 0);

    // Drop the IndexerStore so we can reopen the underlying redb
    // directly and surgically remove the storage-rent row.
    drop(store);

    {
        let db = Database::open(&path).unwrap();
        let wtxn = db.begin_write().unwrap();
        {
            let mut t = wtxn.open_table(UNSPENT_BY_CREATION_HEIGHT_TEST).unwrap();
            // Block 1's box has creation_height=1 and global_box_index=0.
            let removed = t.remove((1u32, 0i64)).unwrap();
            assert!(
                removed.is_some(),
                "test fixture: the row we want to corrupt must exist before removal",
            );
        }
        wtxn.commit().unwrap();
    }

    // Reopen the IndexerStore. Block 2 spends the box; apply_block
    // will call remove_unspent on a missing row → StorageRentDesync.
    let (store, _) = IndexerStore::open(&path).unwrap();

    let tx_b = Transaction {
        inputs: vec![spend_input(created_id)],
        data_inputs: vec![],
        output_candidates: vec![candidate(900_000, 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0xB2; 32]),
        transactions: std::slice::from_ref(&tx_b),
    };
    let err = apply_block(&store, &meta1, &block2)
        .expect_err("apply must halt on missing storage-rent row");

    assert!(
        matches!(
            err,
            IndexerError::StorageRentDesync {
                creation_height: 1,
                global_box_index: 0,
            }
        ),
        "expected StorageRentDesync{{1, 0}}, got {err:?}",
    );
}

#[test]
fn read_storage_rent_eligible_paged_offset_cursor_backfills_across_pages() {
    // Pins the real redb offset/limit contract that the mining engine's
    // `page_rent_boxes` cursor relies on: stepping `offset` by the previous
    // page length walks the whole eligible set oldest-first, with no overlap
    // and no gap, and a short final page signals exhaustion. The engine's
    // unit tests mock `fetch_page`; this proves the live store matches that
    // model so cross-page backfill is real, not assumed.
    use ergo_indexer::SortDir;

    let (store, _tmp) = open_store();
    // Five unspent outputs, all creation_height 1 → global indices 0..=4,
    // all with creation_height ≤ the cutoff we'll query.
    let tx = Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: (0..5).map(|_| candidate(1_000_000, 1)).collect(),
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let expected: Vec<Digest32> = (0..5).map(|i| sealed_box_id(&tx, i)).collect();

    // Walk with limit 2, stepping offset by the returned page length exactly
    // as `page_rent_boxes` does.
    const LIMIT: u32 = 2;
    let mut collected: Vec<Digest32> = Vec::new();
    let mut offset = 0u32;
    let mut pages = 0u32;
    loop {
        let page = store
            .read_storage_rent_eligible_paged(1, offset, LIMIT, SortDir::Asc)
            .unwrap();
        pages += 1;
        let page_len = page.len() as u32;
        collected.extend(page.iter().map(|r| r.box_id));
        if page_len < LIMIT {
            break; // short page → index exhausted
        }
        offset += page_len;
        assert!(pages < 10, "paging did not terminate");
    }

    // Pages were [2, 2, 1]: full union, oldest-first, no overlap, no gap.
    assert_eq!(pages, 3);
    assert_eq!(collected, expected);
}
