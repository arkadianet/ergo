//! Header chain index persistence tests.

use ergo_state::chain::HeaderMeta;
use ergo_state::store::StateStore;
use tempfile::TempDir;

fn fake_meta(parent: [u8; 32], height: u32) -> HeaderMeta {
    HeaderMeta {
        parent_id: parent,
        height,
        cumulative_score: vec![0x01, height as u8],
        pow_validity: 1,
        timestamp: 1_700_000_000 + height as u64,
    }
}

// ----- happy path -----

#[test]
fn empty_store_has_no_header_chain_entries() {
    let dir = TempDir::new().unwrap();
    let store = StateStore::open(&dir.path().join("db")).unwrap();
    assert_eq!(store.get_header_id_at_height(1).unwrap(), None);
    assert_eq!(store.get_header_id_at_height(1_000_000).unwrap(), None);
}

#[test]
fn lookup_at_height_on_empty_store_reports_above_tip() {
    // best_header_height starts at 0; any positive height is AboveTip.
    use ergo_state::chain::HeightLookup;
    let dir = TempDir::new().unwrap();
    let store = StateStore::open(&dir.path().join("db")).unwrap();
    assert!(matches!(
        store.lookup_header_at_height(1).unwrap(),
        HeightLookup::AboveTip
    ));
    assert!(matches!(
        store.lookup_header_at_height(1_000_000).unwrap(),
        HeightLookup::AboveTip
    ));
}

#[test]
fn lookup_at_height_returns_dense_after_header_stored() {
    use ergo_state::chain::HeightLookup;
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    let id1 = [0xAA; 32];
    let meta1 = fake_meta([0u8; 32], 1);
    store
        .store_validated_header(
            &id1,
            &[0u8; 8],
            &meta1,
            Some((1, meta1.cumulative_score.clone())),
        )
        .unwrap();

    match store.lookup_header_at_height(1).unwrap() {
        HeightLookup::Dense(id) => assert_eq!(id, id1),
        other => panic!("expected Dense(id), got {other:?}"),
    }
    // Height 2 is still AboveTip — only height 1 was stored.
    assert!(matches!(
        store.lookup_header_at_height(2).unwrap(),
        HeightLookup::AboveTip
    ));
}

#[test]
fn range_scan_on_empty_store_returns_empty_vec() {
    let dir = TempDir::new().unwrap();
    let store = StateStore::open(&dir.path().join("db")).unwrap();
    let scanned = store.scan_header_chain_range(1, 100).unwrap();
    assert!(scanned.is_empty());
}

#[test]
fn sentinel_absent_on_fresh_store() {
    let dir = TempDir::new().unwrap();
    let store = StateStore::open(&dir.path().join("db")).unwrap();
    assert_eq!(store.header_chain_index_version().unwrap(), None);
}

#[test]
fn non_batched_extension_inserts_entry() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();

    let id1 = [0xAA; 32];
    let meta1 = fake_meta([0u8; 32], 1);
    store
        .store_validated_header(
            &id1,
            &[0u8; 8],
            &meta1,
            Some((1, meta1.cumulative_score.clone())),
        )
        .unwrap();
    assert_eq!(store.get_header_id_at_height(1).unwrap(), Some(id1));

    let id2 = [0xBB; 32];
    let meta2 = fake_meta(id1, 2);
    store
        .store_validated_header(
            &id2,
            &[0u8; 8],
            &meta2,
            Some((2, meta2.cumulative_score.clone())),
        )
        .unwrap();
    assert_eq!(store.get_header_id_at_height(1).unwrap(), Some(id1));
    assert_eq!(store.get_header_id_at_height(2).unwrap(), Some(id2));
    assert_eq!(store.get_header_id_at_height(3).unwrap(), None);
}

#[test]
fn non_batched_fork_flip_rewrites_from_fork_point() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();

    // Old chain g->A1->A2->A3 (all become best as they're validated).
    let g = [0x01; 32];
    let a1 = [0xA1; 32];
    let a2 = [0xA2; 32];
    let a3 = [0xA3; 32];
    for (id, parent, h) in [(g, [0u8; 32], 1), (a1, g, 2), (a2, a1, 3), (a3, a2, 4)] {
        let meta = fake_meta(parent, h);
        store
            .store_validated_header(
                &id,
                &[0u8; 8],
                &meta,
                Some((h, meta.cumulative_score.clone())),
            )
            .unwrap();
    }
    assert_eq!(store.get_header_id_at_height(4).unwrap(), Some(a3));

    // Siblings B2, B3, B4 validated but NOT best (new_best = None).
    let b2 = [0xB2; 32];
    let b3 = [0xB3; 32];
    let b4 = [0xB4; 32];
    for (id, parent, h) in [(b2, a1, 3), (b3, b2, 4), (b4, b3, 5)] {
        let meta = fake_meta(parent, h);
        store
            .store_validated_header(&id, &[0u8; 8], &meta, None)
            .unwrap();
    }
    // Old chain still in index.
    assert_eq!(store.get_header_id_at_height(3).unwrap(), Some(a2));
    assert_eq!(store.get_header_id_at_height(4).unwrap(), Some(a3));
    assert_eq!(store.get_header_id_at_height(5).unwrap(), None);

    // B5 arrives and IS new best — flip fires.
    let b5 = [0xB5; 32];
    let b5_meta = fake_meta(b4, 6);
    let heavy = vec![0xFF];
    store
        .store_validated_header(&b5, &[0u8; 8], &b5_meta, Some((6, heavy)))
        .unwrap();

    assert_eq!(store.get_header_id_at_height(1).unwrap(), Some(g));
    assert_eq!(store.get_header_id_at_height(2).unwrap(), Some(a1));
    assert_eq!(store.get_header_id_at_height(3).unwrap(), Some(b2));
    assert_eq!(store.get_header_id_at_height(4).unwrap(), Some(b3));
    assert_eq!(store.get_header_id_at_height(5).unwrap(), Some(b4));
    assert_eq!(store.get_header_id_at_height(6).unwrap(), Some(b5));
}

#[test]
fn fork_flip_with_shorter_heavier_chain_deletes_old_tail() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();

    let g = [0x01; 32];
    let a1 = [0xA1; 32];
    let a2 = [0xA2; 32];
    let a3 = [0xA3; 32];
    for (id, parent, h) in [(g, [0u8; 32], 1), (a1, g, 2), (a2, a1, 3), (a3, a2, 4)] {
        let meta = fake_meta(parent, h);
        store
            .store_validated_header(
                &id,
                &[0u8; 8],
                &meta,
                Some((h, meta.cumulative_score.clone())),
            )
            .unwrap();
    }

    // Sibling b2 at height 2 validated. Then b2 becomes best (heavier than a3
    // despite being at lower height — synthetic test).
    let b2 = [0xB2; 32];
    let b2_meta = fake_meta(g, 2);
    store
        .store_validated_header(&b2, &[0u8; 8], &b2_meta, None)
        .unwrap();
    // Force-flip via a heavier-score update. In production this flip only
    // happens through finalize_header's is_new_best logic; here we simulate
    // by calling store_validated_header on b2 AGAIN with new_best set.
    let heavy = vec![0xFF];
    store
        .store_validated_header(&b2, &[0u8; 8], &b2_meta, Some((2, heavy)))
        .unwrap();

    // Index should contain g, b2 and NOTHING at heights 3, 4.
    assert_eq!(store.get_header_id_at_height(1).unwrap(), Some(g));
    assert_eq!(store.get_header_id_at_height(2).unwrap(), Some(b2));
    assert_eq!(store.get_header_id_at_height(3).unwrap(), None);
    assert_eq!(store.get_header_id_at_height(4).unwrap(), None);
}

#[test]
fn batch_with_only_best_chain_headers_populates_index() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    store.begin_header_batch();

    let id1 = [0x11; 32];
    let meta1 = fake_meta([0u8; 32], 1);
    store
        .store_validated_header(
            &id1,
            &[0u8; 8],
            &meta1,
            Some((1, meta1.cumulative_score.clone())),
        )
        .unwrap();
    let id2 = [0x22; 32];
    let meta2 = fake_meta(id1, 2);
    store
        .store_validated_header(
            &id2,
            &[0u8; 8],
            &meta2,
            Some((2, meta2.cumulative_score.clone())),
        )
        .unwrap();

    // Not yet flushed → no entries
    assert_eq!(store.get_header_id_at_height(1).unwrap(), None);

    store.flush_header_batch().unwrap();
    assert_eq!(store.get_header_id_at_height(1).unwrap(), Some(id1));
    assert_eq!(store.get_header_id_at_height(2).unwrap(), Some(id2));
}

#[test]
fn batch_mixing_best_and_fork_headers_only_indexes_best_chain() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    store.begin_header_batch();

    // Buffer: A1 (best), A2 (best), B2 (sibling fork, NOT best).
    let a1 = [0xA1; 32];
    let a2 = [0xA2; 32];
    let b2 = [0xB2; 32];
    let ma1 = fake_meta([0u8; 32], 1);
    let ma2 = fake_meta(a1, 2);
    let mb2 = fake_meta(a1, 2);
    store
        .store_validated_header(
            &a1,
            &[0u8; 8],
            &ma1,
            Some((1, ma1.cumulative_score.clone())),
        )
        .unwrap();
    store
        .store_validated_header(
            &a2,
            &[0u8; 8],
            &ma2,
            Some((2, ma2.cumulative_score.clone())),
        )
        .unwrap();
    store
        .store_validated_header(&b2, &[0u8; 8], &mb2, None)
        .unwrap(); // fork, not best

    store.flush_header_batch().unwrap();

    // Only a1 and a2 should be indexed. b2 must NOT overwrite a2.
    assert_eq!(store.get_header_id_at_height(1).unwrap(), Some(a1));
    assert_eq!(store.get_header_id_at_height(2).unwrap(), Some(a2));
}

#[test]
fn same_height_heavier_sibling_flip_across_batches_rewrites_tip() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();

    // Batch 1: commit g, a1 (heights 1, 2) as the best chain.
    store.begin_header_batch();
    let g = [0x01; 32];
    let a1 = [0xA1; 32];
    let mg = fake_meta([0u8; 32], 1);
    let ma1 = fake_meta(g, 2);
    store
        .store_validated_header(&g, &[0u8; 8], &mg, Some((1, mg.cumulative_score.clone())))
        .unwrap();
    store
        .store_validated_header(
            &a1,
            &[0u8; 8],
            &ma1,
            Some((2, ma1.cumulative_score.clone())),
        )
        .unwrap();
    store.flush_header_batch().unwrap();
    assert_eq!(store.get_header_id_at_height(2).unwrap(), Some(a1));

    // Batch 2: a heavier sibling b1 at height 2 becomes best.
    store.begin_header_batch();
    let b1 = [0xB1; 32];
    let mb1 = fake_meta(g, 2);
    let heavy = vec![0xFF];
    store
        .store_validated_header(&b1, &[0u8; 8], &mb1, Some((2, heavy)))
        .unwrap();
    store.flush_header_batch().unwrap();

    assert_eq!(store.get_header_id_at_height(1).unwrap(), Some(g));
    assert_eq!(store.get_header_id_at_height(2).unwrap(), Some(b1));
}

#[test]
fn backfill_populates_index_when_sentinel_absent() {
    use redb::Database;
    use std::sync::Arc;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("db");

    // Populate headers, then manually wipe HEADER_CHAIN_INDEX + sentinel
    // to simulate a pre-upgrade DB.
    {
        let mut store = StateStore::open(&db_path).unwrap();
        let mut parent = [0u8; 32];
        for h in 1..=5u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&h.to_be_bytes());
            let meta = fake_meta(parent, h);
            store
                .store_validated_header(
                    &id,
                    &[0u8; 8],
                    &meta,
                    Some((h, meta.cumulative_score.clone())),
                )
                .unwrap();
            parent = id;
        }
        drop(store);

        let db = Arc::new(Database::create(&db_path).unwrap());
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        {
            let mut idx = txn
                .open_table(redb::TableDefinition::<u64, &[u8]>::new(
                    "header_chain_index",
                ))
                .unwrap();
            for h in 1..=5u64 {
                idx.remove(h).unwrap();
            }
            let mut meta = txn
                .open_table(redb::TableDefinition::<&str, &[u8]>::new("state_meta"))
                .unwrap();
            meta.remove("hci_version").unwrap();
        }
        txn.commit().unwrap();
    }

    // Reopen — backfill must populate the index and set the sentinel.
    let store = StateStore::open(&db_path).unwrap();
    for h in 1..=5u32 {
        let id = store.get_header_id_at_height(h).unwrap().unwrap();
        assert_eq!(&id[..4], &h.to_be_bytes());
    }
    assert_eq!(store.header_chain_index_version().unwrap(), Some(1));
}

#[test]
fn backfill_drains_stale_entries_before_writing_walked_chain() {
    use redb::Database;
    use std::sync::Arc;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("db");

    // Populate a 3-header chain via the normal API.
    {
        let mut store = StateStore::open(&db_path).unwrap();
        let mut parent = [0u8; 32];
        for h in 1..=3u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&h.to_be_bytes());
            let meta = fake_meta(parent, h);
            store
                .store_validated_header(
                    &id,
                    &[0u8; 8],
                    &meta,
                    Some((h, meta.cumulative_score.clone())),
                )
                .unwrap();
            parent = id;
        }
    }

    // Corrupt: inject stale entries at heights 4 and 5 AND clear the
    // sentinel. This simulates the hazard the drain protects against.
    {
        let db = Arc::new(Database::create(&db_path).unwrap());
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        {
            let mut idx = txn
                .open_table(redb::TableDefinition::<u64, &[u8]>::new(
                    "header_chain_index",
                ))
                .unwrap();
            let stale = [0xDE; 32];
            idx.insert(4u64, stale.as_slice()).unwrap();
            idx.insert(5u64, stale.as_slice()).unwrap();
            let mut meta = txn
                .open_table(redb::TableDefinition::<&str, &[u8]>::new("state_meta"))
                .unwrap();
            meta.remove("hci_version").unwrap();
        }
        txn.commit().unwrap();
    }

    // Reopen — backfill must drain stale entries before inserting.
    let store = StateStore::open(&db_path).unwrap();
    assert_eq!(store.get_header_id_at_height(4).unwrap(), None);
    assert_eq!(store.get_header_id_at_height(5).unwrap(), None);
    for h in 1..=3u32 {
        let id = store.get_header_id_at_height(h).unwrap().unwrap();
        assert_eq!(&id[..4], &h.to_be_bytes());
    }
    assert_eq!(store.header_chain_index_version().unwrap(), Some(1));
}

#[test]
fn backfill_runs_first_reopen_then_skipped_on_subsequent_reopens() {
    // Sequence:
    // 1. Fresh open: best_header_height=0, backfill no-ops, sentinel NOT set.
    // 2. Write a header: CHAIN_STATE_META.best_header_height becomes 1,
    //    HEADER_CHAIN_INDEX gets the entry, sentinel still NOT set.
    // 3. Second open: backfill sees sentinel absent + best_header_height=1,
    //    runs (drains, walks, inserts), sets sentinel = Some(1).
    // 4. Third open: backfill sees sentinel present, returns immediately.
    //    THIS is the skip behavior we're verifying.
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("db");
    {
        let mut store = StateStore::open(&db_path).unwrap();
        let id = [0xAB; 32];
        let meta = fake_meta([0u8; 32], 1);
        store
            .store_validated_header(
                &id,
                &[0u8; 8],
                &meta,
                Some((1, meta.cumulative_score.clone())),
            )
            .unwrap();
    }
    // Second open: backfill runs, sets sentinel.
    {
        let store = StateStore::open(&db_path).unwrap();
        assert_eq!(store.header_chain_index_version().unwrap(), Some(1));
    }
    // Third open: sentinel already set, backfill must skip.
    let t0 = std::time::Instant::now();
    let store = StateStore::open(&db_path).unwrap();
    let elapsed = t0.elapsed();
    assert_eq!(store.header_chain_index_version().unwrap(), Some(1));
    assert!(elapsed.as_millis() < 500, "third open took {elapsed:?}");
}
