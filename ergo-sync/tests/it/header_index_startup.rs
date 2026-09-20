//! Verifies that startup loads the header index from HEADER_CHAIN_INDEX
//! via a bounded range-scan, and that coverage gaps fail loudly rather
//! than silently degrading sync.

use ergo_state::chain::HeaderMeta;
use ergo_state::store::StateStore;
use tempfile::TempDir;

use ergo_crypto::difficulty::DifficultyParams;
use ergo_sync::executor::SyncExecutor;
use ergo_validation::context::ProtocolParams;

fn meta(parent: [u8; 32], h: u32) -> HeaderMeta {
    HeaderMeta {
        parent_id: parent,
        height: h,
        cumulative_score: vec![h as u8],
        pow_validity: 1,
        timestamp: 1,
    }
}

#[test]
fn load_header_index_covers_full_gap_and_is_fast() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("db");
    let mut store = StateStore::open(&db_path).unwrap();

    let mut parent = [0u8; 32];
    for h in 1..=200u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&h.to_be_bytes());
        let m = meta(parent, h);
        store
            .store_validated_header(&id, &[0u8; 8], &m, Some((h, m.cumulative_score.clone())))
            .unwrap();
        parent = id;
    }
    drop(store);

    let store = ergo_state::StateBackendKind::Utxo(StateStore::open(&db_path).unwrap());
    let mut exec = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );

    let t0 = std::time::Instant::now();
    exec.load_header_index(&store)
        .expect("load_header_index should succeed");
    let elapsed = t0.elapsed();

    assert!(
        elapsed.as_millis() < 200,
        "load took {elapsed:?}, expected <200ms"
    );
    assert_eq!(exec.header_index_len(), 200);
    for h in 1..=200u32 {
        let id = exec.header_index_get(h).expect("missing height");
        assert_eq!(&id[..4], &h.to_be_bytes());
    }
}

#[test]
fn load_header_index_fails_loud_on_coverage_gap() {
    use redb::Database;
    use std::sync::Arc;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("db");

    // Step 1: write 5 headers through the normal API.
    {
        let mut store = StateStore::open(&db_path).unwrap();
        let mut parent = [0u8; 32];
        for h in 1..=5u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&h.to_be_bytes());
            let m = meta(parent, h);
            store
                .store_validated_header(&id, &[0u8; 8], &m, Some((h, m.cumulative_score.clone())))
                .unwrap();
            parent = id;
        }
    }

    // Step 2: reopen to trigger backfill, which sets hci_version = [1].
    // Without this, step 4's open would trigger backfill and REPAIR the
    // gap we inject in step 3 — the test would then spuriously pass on
    // the repaired index rather than verifying strict-load rejection.
    {
        let store = StateStore::open(&db_path).unwrap();
        assert_eq!(store.header_chain_index_version().unwrap(), Some(1));
    }

    // Step 3: corrupt the index by removing height 3. Leave the sentinel
    // intact so subsequent backfill skips.
    {
        let db = Arc::new(Database::create(&db_path).unwrap());
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn
                .open_table(redb::TableDefinition::<u64, &[u8]>::new(
                    "header_chain_index",
                ))
                .unwrap();
            t.remove(3u64).unwrap();
        }
        txn.commit().unwrap();
    }

    // Step 4: reopen — backfill sees sentinel present, skips. The gap
    // remains. load_header_index must fail with the specific IndexGap
    // variant (not just any error — a generic is_err() could mask an
    // unrelated storage regression passing the test accidentally).
    let store = ergo_state::StateBackendKind::Utxo(StateStore::open(&db_path).unwrap());
    let mut exec = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    match exec.load_header_index(&store) {
        Err(ergo_sync::executor::StartupError::IndexGap {
            lo,
            hi,
            expected,
            got,
        }) => {
            assert_eq!(lo, 1);
            assert_eq!(hi, 5);
            assert_eq!(expected, 5);
            assert_eq!(got, 4, "expected 1 missing entry (height 3 removed)");
        }
        other => panic!("expected StartupError::IndexGap, got {other:?}"),
    }
}
