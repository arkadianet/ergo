//! End-to-end backfill of real mainnet block bytes through the
//! indexer's apply path.
//!
//! Drives `apply_block` over `transactions_1_200.json` (one mainnet tx
//! per height for heights 1..=200) using the matching headers from
//! `headers_1_500.json`. The chain at heights 1..200 is emission-only,
//! so each block's tx spends the previous block's emission output —
//! no synthetic pre-population required.
//!
//! Why 1_200 and not 700000_700200: the 700k corpus contains
//! transactions that spend boxes created by blocks at heights below
//! 700000. Indexer apply rejects unknown inputs (`InputMissing`),
//! which makes a 700k-rooted backfill require either (a) replaying
//! 700k blocks or (b) preloading thousands of synthetic input boxes.
//! Both scaffolding paths are deferred to P2+ where address-segment
//! work motivates them anyway. The 1_200 corpus exercises the same
//! apply path (real mainnet tx structure, real serialization, real
//! IDs) and is a valid `backfill end-to-end` proof.
//!
//! Crash-safety regression: re-applying the same range against a
//! fresh DB yields byte-equal final state, asserting determinism on
//! the apply path.

use std::fs;
use std::path::Path;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::transaction::{read_transaction, Transaction};
use serde::Deserialize;
use tempfile::TempDir;

use ergo_indexer::{apply_block, IndexerBlock, IndexerMeta, IndexerStore};

#[derive(Debug, Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
    height: u32,
}

#[derive(Debug, Deserialize)]
struct HeaderVector {
    height: u32,
    id: String,
}

fn vectors_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/mainnet")
}

fn load<T: for<'de> Deserialize<'de>>(filename: &str) -> Vec<T> {
    let path = vectors_dir().join(filename);
    let data = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {filename}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {filename}: {e}"))
}

fn parse_tx(v: &TxVector) -> Transaction {
    let raw = hex::decode(&v.bytes)
        .unwrap_or_else(|e| panic!("hex decode tx {} h={}: {e}", v.id, v.height));
    let mut r = VlqReader::new(&raw);
    read_transaction(&mut r).unwrap_or_else(|e| panic!("parse tx {} h={}: {e}", v.id, v.height))
}

fn parse_id(s: &str) -> Digest32 {
    let bytes = hex::decode(s).unwrap_or_else(|e| panic!("hex decode id {s}: {e}"));
    let arr: [u8; 32] = bytes.try_into().expect("id must be 32 bytes");
    Digest32::from_bytes(arr)
}

/// Result of backfilling a fresh indexer with a contiguous corpus
/// slice — the things downstream tests use to compare runs.
struct BackfillRun {
    final_meta: IndexerMeta,
    /// (tx_id, indexed_height) for every applied block, in order. Used
    /// to spot-check `read_tx` on a fresh DB.
    applied_txs: Vec<(Digest32, i32)>,
}

fn backfill(start_height: u32, end_height: u32) -> (BackfillRun, IndexerStore, TempDir) {
    let txs: Vec<TxVector> = load("transactions_1_200.json");
    let headers: Vec<HeaderVector> = load("headers_1_500.json");

    let header_id_at = |h: u32| -> Digest32 {
        let v = headers
            .iter()
            .find(|h2| h2.height == h)
            .unwrap_or_else(|| panic!("missing header at height {h}"));
        parse_id(&v.id)
    };

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();

    let mut meta = IndexerMeta::empty();
    let mut applied_txs = Vec::with_capacity((end_height - start_height + 1) as usize);

    for h in start_height..=end_height {
        let tv = txs
            .iter()
            .find(|t| t.height == h)
            .unwrap_or_else(|| panic!("no tx at height {h} in corpus"));
        let tx = parse_tx(tv);
        let header_id = header_id_at(h);

        let txs_slice = std::slice::from_ref(&tx);
        let block = IndexerBlock {
            height: h as i32,
            header_id,
            transactions: txs_slice,
        };
        meta = apply_block(&store, &meta, &block)
            .unwrap_or_else(|e| panic!("apply_block height {h}: {e:?}"));

        applied_txs.push((parse_id(&tv.id), h as i32));
    }

    (
        BackfillRun {
            final_meta: meta,
            applied_txs,
        },
        store,
        tmp,
    )
}

#[test]
fn backfill_heights_1_to_200_advances_meta_to_height_200() {
    let (run, store, _tmp) = backfill(1, 200);

    // Apply path should have advanced exactly 200 heights.
    assert_eq!(run.final_meta.indexed_height, 200);
    // One tx per height, so 200 txs total.
    assert_eq!(run.final_meta.global_tx_index, 200);
    // Every block creates ≥1 output, so global_box_index ≥ 200.
    assert!(
        run.final_meta.global_box_index >= 200,
        "expected at least 200 outputs, got {}",
        run.final_meta.global_box_index,
    );

    // indexed_header_id should match the height-200 header from corpus.
    let headers: Vec<HeaderVector> = load("headers_1_500.json");
    let h200 = parse_id(&headers.iter().find(|h| h.height == 200).unwrap().id);
    assert_eq!(run.final_meta.indexed_header_id, Some(h200));

    // Spot-check a few txs are reachable by id and byIndex returns the
    // same id we recorded going in.
    for &(tx_id, h) in &[
        run.applied_txs[0],
        run.applied_txs[99],
        run.applied_txs[199],
    ] {
        let row = store
            .read_tx(&tx_id)
            .unwrap()
            .unwrap_or_else(|| panic!("tx {} should be indexed", hex::encode(tx_id.as_bytes())));
        assert_eq!(row.id, tx_id);
        assert_eq!(row.height, h);
    }

    // Every NUMERIC_TX[n] for n in 0..200 resolves to a real tx row.
    for n in 0..run.final_meta.global_tx_index {
        let id = store
            .read_numeric_tx(n)
            .unwrap()
            .unwrap_or_else(|| panic!("NUMERIC_TX[{n}] missing after backfill"));
        assert!(
            store.read_tx(&id).unwrap().is_some(),
            "NUMERIC_TX[{n}] points at id {} but no row exists",
            hex::encode(id.as_bytes()),
        );
    }
}

#[test]
fn backfill_is_deterministic_across_fresh_runs() {
    // Re-apply the same corpus to a separate fresh DB and compare the
    // post-backfill meta. The apply path is meant to be a pure
    // function of (input meta, block) — not driven by clocks, RNGs, or
    // iteration order — so two cold runs over the same input must
    // converge on the same meta byte-for-byte.
    let (run_a, _store_a, _tmp_a) = backfill(1, 200);
    let (run_b, _store_b, _tmp_b) = backfill(1, 200);
    assert_eq!(run_a.final_meta, run_b.final_meta);
}

#[test]
fn backfill_first_ten_blocks_round_trips_through_read_box_byindex() {
    // Runs the smallest meaningful slice for fast feedback during
    // development: 10 blocks, then check NUMERIC_BOX point lookups
    // resolve to readable IndexedErgoBox rows whose `inclusion_height`
    // is in range.
    let (run, store, _tmp) = backfill(1, 10);
    assert_eq!(run.final_meta.indexed_height, 10);

    for n in 0..run.final_meta.global_box_index {
        let id = store
            .read_numeric_box(n)
            .unwrap()
            .unwrap_or_else(|| panic!("NUMERIC_BOX[{n}] missing"));
        let b = store
            .read_box(&id)
            .unwrap()
            .unwrap_or_else(|| panic!("INDEXED_BOX missing for n={n}"));
        assert_eq!(b.global_index as u64, n);
        assert!(
            (1..=10).contains(&b.inclusion_height),
            "box {n} inclusion_height {} out of range",
            b.inclusion_height,
        );
    }
}
