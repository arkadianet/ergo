//! Mode 3 Phase 1a — `STATE_META[minimal_full_block_height_v1]`
//! sentinel + `SECTION_HEIGHT_INDEX` infrastructure.
//!
//! - `init → read → advance → reopen` lifecycle across the four
//!   simple sentinel-seed cases.
//! - Monotonicity guard: writes below the current sentinel fail
//!   with the typed `PruneSentinelMonotonicity` variant.
//! - `store_header` populates `SECTION_HEIGHT_INDEX` for the
//!   header's 3 derived section ids atomically.
//! - `back_fill_section_height_index` walks legacy archive DBs
//!   and stamps the `SECTION_HEIGHT_BACKFILL_DONE_V1` sentinel
//!   after a populated pass; subsequent runs short-circuit.

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{write_header, Header};
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::store::StateStore;
use std::path::PathBuf;

// ----- helpers -----

fn tempdir_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    (dir, path)
}

fn open(path: &std::path::Path) -> StateStore {
    StateStore::open_with_cache(path, 4 * 1024 * 1024).unwrap()
}

/// Minimal v2 header with caller-controlled roots so tests can
/// derive the 3 section ids deterministically.
fn synth_header(
    parent_id: [u8; 32],
    height: u32,
    ad_proofs_root: [u8; 32],
    transactions_root: [u8; 32],
    extension_root: [u8; 32],
) -> Vec<u8> {
    let header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent_id),
        ad_proofs_root: Digest32::from_bytes(ad_proofs_root),
        transactions_root: Digest32::from_bytes(transactions_root),
        state_root: ADDigest::from_bytes([0x04; 33]),
        timestamp: 1_700_000_000_000,
        extension_root: Digest32::from_bytes(extension_root),
        n_bits: 0x1a01_7660,
        height,
        votes: [0x00, 0x00, 0x00],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x02; 33]),
            nonce: [0xAA; 8],
        },
    };
    let mut w = VlqWriter::new();
    write_header(&mut w, &header).expect("synthetic header fits wire bounds");
    w.result()
}

// ----- happy path -----

#[test]
fn fresh_db_read_returns_genesis_height_default_without_eager_seed() {
    let (_d, path) = tempdir_path();
    let store = open(&path);
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        1,
        "Absent-key read returns GenesisHeight (=1) as the legitimate \
         default for archive / Mode 6 / fresh DBs. Phase 1a deliberately \
         does NOT durably seed the key on open so Phase 1b's \
         bootstrap-aware seeding can write a different value without \
         migrating around an eager stamp.",
    );
}

#[test]
fn sentinel_survives_reopen() {
    let (_d, path) = tempdir_path();
    {
        let store = open(&path);
        store.write_minimal_full_block_height(42).unwrap();
        assert_eq!(store.read_minimal_full_block_height().unwrap(), 42);
    }
    let store = open(&path);
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        42,
        "sentinel must survive a reopen — STATE_META is persisted",
    );
}

#[test]
fn sentinel_advances_monotonically() {
    let (_d, path) = tempdir_path();
    let store = open(&path);
    store.write_minimal_full_block_height(10).unwrap();
    store.write_minimal_full_block_height(50).unwrap();
    store.write_minimal_full_block_height(1024).unwrap();
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 1024);
}

// ----- error paths -----

#[test]
fn sentinel_rejects_backward_advance() {
    use ergo_state::store::StateError;
    let (_d, path) = tempdir_path();
    let store = open(&path);
    store.write_minimal_full_block_height(100).unwrap();
    let err = store
        .write_minimal_full_block_height(50)
        .expect_err("backward advance must reject");
    match err {
        StateError::PruneSentinelMonotonicity { current, attempted } => {
            assert_eq!(current, 100);
            assert_eq!(attempted, 50);
        }
        other => panic!(
            "expected PruneSentinelMonotonicity, got {other:?} — \
             once block-section data is gone the sentinel must \
             stay at the high-water mark",
        ),
    }
}

#[test]
fn sentinel_accepts_same_value_idempotent() {
    let (_d, path) = tempdir_path();
    let store = open(&path);
    store.write_minimal_full_block_height(100).unwrap();
    store.write_minimal_full_block_height(100).unwrap();
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 100);
}

// ----- section-height index -----

#[test]
fn store_header_writes_section_height_index_for_three_section_ids() {
    let (_d, path) = tempdir_path();
    let store = open(&path);
    let header_id = [0xAAu8; 32];
    let ad_proofs_root = [0x01; 32];
    let transactions_root = [0x02; 32];
    let extension_root = [0x03; 32];
    let header_bytes = synth_header(
        [0; 32],
        12_345,
        ad_proofs_root,
        transactions_root,
        extension_root,
    );
    store.store_header(&header_id, &header_bytes).unwrap();

    for (type_byte, root) in [
        (TYPE_AD_PROOFS, ad_proofs_root),
        (TYPE_BLOCK_TRANSACTIONS, transactions_root),
        (TYPE_EXTENSION, extension_root),
    ] {
        let section_id = compute_section_id(type_byte, &header_id, &root);
        assert_eq!(
            store.get_section_height(&section_id).unwrap(),
            Some(12_345),
            "store_header must tag SECTION_HEIGHT_INDEX[section_id of type {type_byte}] = header.height",
        );
    }
}

#[test]
fn get_section_height_returns_none_for_unknown_id() {
    let (_d, path) = tempdir_path();
    let store = open(&path);
    let unknown = [0xFFu8; 32];
    assert_eq!(store.get_section_height(&unknown).unwrap(), None);
}

// ----- production header-write paths -----
//
// `store_header` is the test-fixture API; the dominant
// production paths are `store_validated_header` (single-header
// sync) and `flush_header_batch` (IBD batched writes). Both must
// populate SECTION_HEIGHT_INDEX in the same atomic write_txn as
// the HEADERS row, otherwise IBD-time headers commit without
// indexing and the next boot's back-fill becomes load-bearing.

use ergo_state::chain::HeaderMeta;

fn fake_meta(parent_id: [u8; 32], height: u32) -> HeaderMeta {
    HeaderMeta {
        parent_id,
        height,
        cumulative_score: vec![0u8; 8],
        pow_validity: 1,
        timestamp: 0,
    }
}

#[test]
fn store_validated_header_writes_section_height_index() {
    let (_d, path) = tempdir_path();
    let mut store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
    let header_id = [0x55u8; 32];
    let ad_root = [0x91; 32];
    let tx_root = [0x92; 32];
    let ext_root = [0x93; 32];
    let header_bytes = synth_header([0; 32], 700_000, ad_root, tx_root, ext_root);
    let meta = fake_meta([0; 32], 700_000);
    // Pass `None` for new_best to skip the best-chain index rewrite
    // (which walks parents and would trip on the synthetic chain).
    // The SECTION_HEIGHT_INDEX writes don't depend on the rewrite —
    // they happen unconditionally inside the same write_txn.
    store
        .store_validated_header(&header_id, &header_bytes, &meta, None)
        .unwrap();
    for (type_byte, root) in [
        (TYPE_AD_PROOFS, ad_root),
        (TYPE_BLOCK_TRANSACTIONS, tx_root),
        (TYPE_EXTENSION, ext_root),
    ] {
        let section_id = compute_section_id(type_byte, &header_id, &root);
        assert_eq!(
            store.get_section_height(&section_id).unwrap(),
            Some(700_000),
            "store_validated_header must populate SECTION_HEIGHT_INDEX for \
             section of type {type_byte}",
        );
    }
}

#[test]
fn store_validated_header_rejects_height_mismatch_between_meta_and_bytes() {
    // Invariant: HeaderMeta.height must equal the parsed
    // header_bytes.height. Otherwise HEADER_META / HEADERS_BY_HEIGHT
    // and SECTION_HEIGHT_INDEX would commit different heights
    // for the same header — split-brain metadata. Phase 1a
    // raises HeaderHeightMismatch loud before any row is written.
    use ergo_state::store::StateError;
    let (_d, path) = tempdir_path();
    let mut store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
    let header_id = [0x99u8; 32];
    // Bytes claim height 12345; meta says 99999 — mismatch.
    let header_bytes = synth_header([0; 32], 12_345, [0x01; 32], [0x02; 32], [0x03; 32]);
    let lying_meta = fake_meta([0; 32], 99_999);
    let err = store
        .store_validated_header(&header_id, &header_bytes, &lying_meta, None)
        .expect_err("mismatched height must reject");
    match err {
        StateError::HeaderHeightMismatch { parsed, meta, .. } => {
            assert_eq!(parsed, 12_345);
            assert_eq!(meta, 99_999);
        }
        other => panic!("expected HeaderHeightMismatch, got {other:?}"),
    }
}

#[test]
fn failed_flush_header_batch_clears_batch_overlay_no_phantom_state() {
    // get_header / get_header_meta read batch_headers / batch_meta
    // FIRST and fall back to redb. A failed flush must clear the
    // in-memory overlay or subsequent reads would see uncommitted
    // header bytes that never landed on disk. The clear happens
    // unconditionally in flush_header_batch, including the error
    // path that HeaderHeightMismatch now reaches.
    let (_d, path) = tempdir_path();
    let mut store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
    store.begin_header_batch();
    let id = [0x66u8; 32];
    let header_bytes = synth_header([0; 32], 100, [0xB1; 32], [0xB2; 32], [0xB3; 32]);
    let lying_meta = fake_meta([0; 32], 999); // mismatch
    store
        .store_validated_header(&id, &header_bytes, &lying_meta, None)
        .unwrap();
    // Pre-flush: batched read sees the buffered header.
    assert_eq!(
        store.get_header(&id).unwrap().unwrap(),
        header_bytes,
        "during batch, get_header reads from in-memory overlay",
    );
    // Flush fails with HeaderHeightMismatch.
    assert!(store.flush_header_batch().is_err());
    // Post-flush: overlay cleared, redb never got the row →
    // get_header returns None.
    assert_eq!(
        store.get_header(&id).unwrap(),
        None,
        "failed flush must clear batch_headers; otherwise the \
         uncommitted bytes leak via the in-memory-first read order",
    );
}

#[test]
fn flush_header_batch_rejects_height_mismatch() {
    use ergo_state::store::StateError;
    let (_d, path) = tempdir_path();
    let mut store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
    store.begin_header_batch();
    let id = [0x44u8; 32];
    let header_bytes = synth_header([0; 32], 100, [0xA1; 32], [0xA2; 32], [0xA3; 32]);
    let lying_meta = fake_meta([0; 32], 200); // bytes say 100, meta says 200
    store
        .store_validated_header(&id, &header_bytes, &lying_meta, None)
        .unwrap();
    let err = store
        .flush_header_batch()
        .expect_err("batched mismatch must reject at flush time");
    match err {
        StateError::HeaderHeightMismatch { parsed, meta, .. } => {
            assert_eq!(parsed, 100);
            assert_eq!(meta, 200);
        }
        other => panic!("expected HeaderHeightMismatch, got {other:?}"),
    }
}

#[test]
fn section_height_backfill_complete_accessor_pins_sentinel_state() {
    // The accessor is the single source of truth for "is the
    // section-height index trustworthy on this DB?". Boot's
    // pruned-mode activation gate reads it before allowing
    // serve-gating to engage; flipping the answer to true
    // requires the back-fill to actually stamp the sentinel.
    let (_d, path) = tempdir_path();
    let store = open(&path);
    assert!(
        !store.section_height_backfill_complete().unwrap(),
        "fresh DB starts with sentinel absent",
    );
    // Run back-fill on a populated DB — sentinel must stamp.
    let header_bytes = synth_header([0; 32], 7, [0xE1; 32], [0xE2; 32], [0xE3; 32]);
    store.store_header(&[0x88u8; 32], &header_bytes).unwrap();
    store.back_fill_section_height_index().unwrap();
    assert!(
        store.section_height_backfill_complete().unwrap(),
        "back-fill on populated DB stamps the sentinel",
    );
}

#[test]
fn flush_header_batch_writes_section_height_index() {
    let (_d, path) = tempdir_path();
    let mut store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
    store.begin_header_batch();
    let id1 = [0xA0u8; 32];
    let id2 = [0xA1u8; 32];
    let header1 = synth_header([0; 32], 1_000, [0x01; 32], [0x02; 32], [0x03; 32]);
    let header2 = synth_header([0xA0; 32], 1_001, [0x11; 32], [0x12; 32], [0x13; 32]);
    let meta1 = fake_meta([0; 32], 1_000);
    let meta2 = fake_meta([0xA0; 32], 1_001);
    // Both writes pass `None` for new_best — flush_header_batch's
    // rewrite path walks parents, which we don't have for the
    // synthetic chain. SECTION_HEIGHT_INDEX writes are unconditional
    // inside the flush's atomic write_txn.
    store
        .store_validated_header(&id1, &header1, &meta1, None)
        .unwrap();
    store
        .store_validated_header(&id2, &header2, &meta2, None)
        .unwrap();
    store.flush_header_batch().unwrap();

    // Both headers' derived section ids must have height rows after flush.
    for (header_id, expected_height, roots) in [
        (id1, 1_000, ([0x01u8; 32], [0x02u8; 32], [0x03u8; 32])),
        (id2, 1_001, ([0x11u8; 32], [0x12u8; 32], [0x13u8; 32])),
    ] {
        let (ad, tx, ext) = roots;
        for (type_byte, root) in [
            (TYPE_AD_PROOFS, ad),
            (TYPE_BLOCK_TRANSACTIONS, tx),
            (TYPE_EXTENSION, ext),
        ] {
            let section_id = compute_section_id(type_byte, &header_id, &root);
            assert_eq!(
                store.get_section_height(&section_id).unwrap(),
                Some(expected_height),
                "flush_header_batch must populate SECTION_HEIGHT_INDEX for \
                 header_id {header_id:?} section of type {type_byte}",
            );
        }
    }
}

// ----- back-fill walk -----

#[test]
fn back_fill_empty_db_stamps_sentinel_so_fresh_mode_3_boot_is_activation_ready() {
    // Phase 1a + Phase 4 contract: a fresh DB opened with
    // `blocks_to_keep > 0` must not fail boot on the
    // SectionHeightBackfillRequired gate. Empty DB has nothing to
    // migrate, so the back-fill stamps the sentinel immediately.
    // Diverges from `MODIFIER_INDEX_BACKFILL_DONE_V1` which
    // never stamps on empty — that sentinel is purely a back-fill
    // short-circuit, not an activation gate.
    let (_d, path) = tempdir_path();
    let store = open(&path);
    assert!(
        !store.section_height_backfill_complete().unwrap(),
        "fresh DB starts with sentinel absent",
    );
    let written = store.back_fill_section_height_index().unwrap();
    assert_eq!(written, 0, "empty DB writes nothing");
    assert!(
        store.section_height_backfill_complete().unwrap(),
        "empty-DB back-fill must stamp the sentinel so Mode 3 boot \
         is activation-ready",
    );
    // Re-run short-circuits via the stamped sentinel.
    assert_eq!(store.back_fill_section_height_index().unwrap(), 0);
}

#[test]
fn back_fill_recovers_legacy_db_with_headers_but_no_section_height_rows() {
    // True legacy-archive migration: write a header into the
    // `headers` table directly (bypassing `store_header`'s
    // SECTION_HEIGHT_INDEX writes), close the DB, reopen via
    // StateStore, then run the back-fill walk. The walk must
    // populate the 3 expected rows for the header AND stamp the
    // sentinel. Re-run short-circuits.
    //
    // Pre-Phase-1a archive DBs had this exact shape — headers on
    // disk, no SECTION_HEIGHT_INDEX rows. The back-fill is the
    // upgrade path; without this test the migration story is
    // only covered indirectly.
    use redb::{Database, ReadableTableMetadata, TableDefinition};
    let (_d, path) = tempdir_path();
    let header_id = [0xCCu8; 32];
    let ad_root = [0x71; 32];
    let tx_root = [0x72; 32];
    let ext_root = [0x73; 32];
    let header_bytes = synth_header([0; 32], 800_000, ad_root, tx_root, ext_root);

    // Raw insert into HEADERS at the redb file level, then close
    // — exactly the shape an old archive DB would have on disk.
    {
        let raw_db = Database::create(&path).unwrap();
        const HEADERS_TBL: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("headers");
        let write_txn = raw_db.begin_write().unwrap();
        {
            let mut t = write_txn.open_table(HEADERS_TBL).unwrap();
            t.insert(header_id.as_slice(), header_bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();
    }
    // Verify the pre-condition: HEADERS row present, no
    // SECTION_HEIGHT_INDEX rows.
    {
        let raw_db = Database::open(&path).unwrap();
        const HEADERS_TBL: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("headers");
        let r = raw_db.begin_read().unwrap();
        let t = r.open_table(HEADERS_TBL).unwrap();
        assert_eq!(t.len().unwrap(), 1, "legacy fixture has 1 HEADERS row");
        // section_height_index table doesn't exist yet — confirms
        // the legacy shape.
        const SHI_TBL: TableDefinition<'_, &[u8], u32> =
            TableDefinition::new("section_height_index");
        assert!(
            matches!(
                r.open_table(SHI_TBL),
                Err(redb::TableError::TableDoesNotExist(_))
            ),
            "legacy fixture has no SECTION_HEIGHT_INDEX rows",
        );
    }

    // Now open via StateStore and run the back-fill — the walk
    // must populate the 3 derived section ids.
    let store = open(&path);
    let written = store.back_fill_section_height_index().unwrap();
    assert_eq!(
        written, 3,
        "legacy header → 3 SECTION_HEIGHT_INDEX rows written by back-fill",
    );
    for (type_byte, root) in [
        (TYPE_AD_PROOFS, ad_root),
        (TYPE_BLOCK_TRANSACTIONS, tx_root),
        (TYPE_EXTENSION, ext_root),
    ] {
        let section_id = compute_section_id(type_byte, &header_id, &root);
        assert_eq!(
            store.get_section_height(&section_id).unwrap(),
            Some(800_000),
            "back-fill writes height row for section_id of type {type_byte}",
        );
    }
    // Re-run short-circuits via the stamped sentinel.
    assert_eq!(store.back_fill_section_height_index().unwrap(), 0);
}

#[test]
fn fresh_db_open_does_not_durably_seed_sentinel() {
    let (_d, path) = tempdir_path();
    // Open once and close without ever calling write_minimal_full_block_height.
    {
        let store = open(&path);
        // Read returns 1 via the absent-key default.
        assert_eq!(store.read_minimal_full_block_height().unwrap(), 1);
    }
    // Re-open. write a different value WITHOUT bumping it from 1
    // first — succeeds because the key was never durably stamped.
    let store = open(&path);
    store
        .write_minimal_full_block_height(5_000)
        .expect("write succeeds — open-time path did not eagerly stamp 1");
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 5_000);
}

#[test]
fn back_fill_with_parse_failure_does_not_stamp_sentinel_so_retry_works() {
    // The back-fill must NOT mark itself complete when it
    // skipped rows. Otherwise one transient parse gap permanently
    // locks out future repair of the index. Test recipe:
    //   1. `store_header` with garbage bytes — HEADERS row lands
    //      (store_header always inserts; parse failure is silent
    //      via `.ok()`), SECTION_HEIGHT_INDEX gets nothing
    //      because the parse path conditional skipped the writes.
    //   2. `back_fill_section_height_index` walks HEADERS, fails
    //      to parse the same bytes, increments `parse_failures`,
    //      RETURNS WITHOUT STAMPING the sentinel.
    //   3. A second call still scans (no sentinel short-circuit)
    //      and still fails — proves retry is alive.
    let (_d, path) = tempdir_path();
    let store = open(&path);
    let garbage = vec![0xFFu8; 64]; // not a valid header at any version
    store.store_header(&[0x77u8; 32], &garbage).unwrap();

    let written = store.back_fill_section_height_index().unwrap();
    assert_eq!(
        written, 0,
        "garbage header → no SECTION_HEIGHT_INDEX rows written",
    );
    // Second call must also scan (sentinel not stamped) and
    // return 0. The sentinel-absent state is the retriable
    // state we want.
    let rerun = store.back_fill_section_height_index().unwrap();
    assert_eq!(
        rerun, 0,
        "second call still walks because sentinel was not stamped",
    );
}

#[test]
fn back_fill_clean_db_stamps_sentinel_and_short_circuits_on_rerun() {
    // Happy path: every header parses cleanly → the back-fill
    // stamps the sentinel after a single pass, and a second call
    // short-circuits via the sentinel.
    let (_d, path) = tempdir_path();
    let store = open(&path);
    let good = synth_header([0; 32], 100, [0xA1; 32], [0xA2; 32], [0xA3; 32]);
    store.store_header(&[0x10u8; 32], &good).unwrap();
    let written = store.back_fill_section_height_index().unwrap();
    assert_eq!(
        written, 0,
        "already-indexed rows (store_header wrote them) → 0 new writes",
    );
    // Re-run short-circuits because the sentinel stamped on the
    // clean pass.
    assert_eq!(store.back_fill_section_height_index().unwrap(), 0);
}

#[test]
fn back_fill_idempotent_across_reopen() {
    let (_d, path) = tempdir_path();
    {
        let store = open(&path);
        let header_bytes = synth_header([0; 32], 5, [0x11; 32], [0x12; 32], [0x13; 32]);
        store.store_header(&[0xAAu8; 32], &header_bytes).unwrap();
        let _ = store.back_fill_section_height_index().unwrap();
    }
    // Reopen and re-run — must short-circuit via persisted sentinel.
    let store = open(&path);
    assert_eq!(
        store.back_fill_section_height_index().unwrap(),
        0,
        "sentinel survives reopen; back-fill returns 0 without scan",
    );
}
