//! Coverage for `MODIFIER_TYPE_INDEX` and `back_fill_modifier_type_index`.
//!
//! - `store_header` tags 101 in the same write txn.
//! - `store_block_section_typed` tags the supplied byte.
//! - `back_fill_modifier_type_index` walks `HEADERS`, parses each
//!   header to recover the three section roots, and tags any matching
//!   entry in `BLOCK_SECTIONS` with `(102, 104, 108)` per
//!   `Blake2b256(typeByte ++ headerId ++ digest)`.
//! - The back-fill is idempotent (subsequent runs return 0).

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{write_header, Header};
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::store::{ModifierIndexBackfillEvent, StateStore};

fn temp_store() -> (tempfile::TempDir, StateStore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
    (dir, store)
}

/// Build a minimal v2 header whose roots are controllable by the test,
/// using the real serializer so back-fill can parse it.
fn write_minimal_header(
    parent_id: [u8; 32],
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
        height: 800_000,
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
fn store_header_tags_modifier_type_101() {
    let (_d, store) = temp_store();
    let header_id = [0xAAu8; 32];
    let header_bytes = write_minimal_header([1; 32], [2; 32], [3; 32], [4; 32]);
    store.store_header(&header_id, &header_bytes).unwrap();

    assert_eq!(store.get_modifier_type(&header_id).unwrap(), Some(101));
}

#[test]
fn store_block_section_typed_tags_section_byte() {
    let (_d, store) = temp_store();
    let id = [0xBBu8; 32];
    store
        .store_block_section_typed(&id, &[0xCC; 64], 102)
        .unwrap();

    assert_eq!(store.get_modifier_type(&id).unwrap(), Some(102));
}

#[test]
fn untyped_store_block_section_leaves_index_empty() {
    let (_d, store) = temp_store();
    let id = [0xDDu8; 32];
    store.store_block_section(&id, &[0xEE; 64]).unwrap();

    // No tag — older write path doesn't populate the index.
    assert_eq!(store.get_modifier_type(&id).unwrap(), None);
}

#[test]
fn back_fill_tags_pre_existing_sections_via_header_roots() {
    let (_d, store) = temp_store();

    let header_id = [0x11u8; 32];
    let parent = [0x10u8; 32];
    let ad_root = [0xA1u8; 32];
    let tx_root = [0xB1u8; 32];
    let ext_root = [0xC1u8; 32];
    let header_bytes = write_minimal_header(parent, ad_root, tx_root, ext_root);
    store.store_header(&header_id, &header_bytes).unwrap();

    // Sections written via the OLD untagged path — simulating a DB
    // that pre-dates the modifier-type index.
    let tx_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &tx_root);
    let ad_id = compute_section_id(TYPE_AD_PROOFS, &header_id, &ad_root);
    let ext_id = compute_section_id(TYPE_EXTENSION, &header_id, &ext_root);
    store.store_block_section(&tx_id, &[0; 64]).unwrap();
    store.store_block_section(&ad_id, &[0; 64]).unwrap();
    store.store_block_section(&ext_id, &[0; 64]).unwrap();

    // Untagged before back-fill (header was tagged at store_header time).
    assert_eq!(store.get_modifier_type(&tx_id).unwrap(), None);
    assert_eq!(store.get_modifier_type(&ad_id).unwrap(), None);
    assert_eq!(store.get_modifier_type(&ext_id).unwrap(), None);

    let n = store.back_fill_modifier_type_index().unwrap();
    assert_eq!(n, 3, "back-fill must tag the three section ids");

    assert_eq!(store.get_modifier_type(&tx_id).unwrap(), Some(102));
    assert_eq!(store.get_modifier_type(&ad_id).unwrap(), Some(104));
    assert_eq!(store.get_modifier_type(&ext_id).unwrap(), Some(108));

    // Idempotent — second run is a no-op.
    let n2 = store.back_fill_modifier_type_index().unwrap();
    assert_eq!(n2, 0, "back-fill must be idempotent");
}

/// Confirm `_with_progress` fires the four lifecycle events in the
/// documented order on a one-header fixture under the streaming
/// implementation. `est_bytes == 0` (no full-table Vec is
/// materialised); `capacity_rows` reports the per-chunk row cap.
#[test]
fn with_progress_emits_events_in_order_one_header() {
    let (_d, store) = temp_store();
    let header_id = [0x21u8; 32];
    let header_bytes = write_minimal_header([0x20; 32], [0xA2; 32], [0xB2; 32], [0xC2; 32]);
    store.store_header(&header_id, &header_bytes).unwrap();
    // One pre-existing section so back-fill writes a non-zero count.
    let tx_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &[0xB2; 32]);
    store.store_block_section(&tx_id, &[0; 32]).unwrap();

    let mut events: Vec<ModifierIndexBackfillEvent> = Vec::new();
    let written = store
        .back_fill_modifier_type_index_with_progress(|ev| events.push(ev))
        .unwrap();
    assert_eq!(written, 1);
    assert_eq!(events.len(), 4, "got: {events:?}");
    assert!(matches!(events[0], ModifierIndexBackfillEvent::Start));
    match events[1] {
        ModifierIndexBackfillEvent::AfterCollect {
            rows,
            est_bytes,
            capacity_rows,
        } => {
            assert_eq!(rows, 1, "exactly one header row counted");
            assert_eq!(
                est_bytes, 0,
                "streaming back-fill: no full-table Vec, so est_bytes is always 0",
            );
            assert!(
                capacity_rows >= rows,
                "capacity_rows is per-chunk cap (informational), expected ≥ rows",
            );
        }
        ref other => panic!("expected AfterCollect, got {other:?}"),
    }
    match events[2] {
        ModifierIndexBackfillEvent::BeforeCommit { rows } => {
            assert_eq!(rows, 1);
        }
        ref other => panic!("expected BeforeCommit, got {other:?}"),
    }
    match events[3] {
        ModifierIndexBackfillEvent::AfterCommit {
            written: w,
            scan_secs,
        } => {
            assert_eq!(w, 1);
            assert!(
                scan_secs.is_finite() && scan_secs >= 0.0,
                "scan_secs must be finite non-negative, got {scan_secs}",
            );
        }
        ref other => panic!("expected AfterCommit, got {other:?}"),
    }
}

/// Same lifecycle on a 5-header fixture: rows count and est_bytes scale.
#[test]
fn with_progress_emits_events_in_order_five_headers() {
    let (_d, store) = temp_store();
    let mut tagged = 0usize;
    for i in 0u8..5 {
        let hid = [0x30 + i; 32];
        let ad = [0xA0 + i; 32];
        let tx = [0xB0 + i; 32];
        let ext = [0xC0 + i; 32];
        let bytes = write_minimal_header([0x2F + i; 32], ad, tx, ext);
        store.store_header(&hid, &bytes).unwrap();
        // Pre-existing untagged section per header → should be tagged.
        let tx_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &hid, &tx);
        store.store_block_section(&tx_id, &[0; 32]).unwrap();
        tagged += 1;
    }

    let mut events: Vec<ModifierIndexBackfillEvent> = Vec::new();
    let written = store
        .back_fill_modifier_type_index_with_progress(|ev| events.push(ev))
        .unwrap();
    assert_eq!(written, tagged);
    assert_eq!(events.len(), 4);
    if let ModifierIndexBackfillEvent::AfterCollect { rows, .. } = events[1] {
        assert_eq!(rows, 5, "all 5 headers collected");
    } else {
        panic!("events[1] must be AfterCollect");
    }
}

#[test]
fn back_fill_skips_orphaned_sections_without_parent_header() {
    let (_d, store) = temp_store();

    // Section bytes present, but no header in HEADERS that produces
    // this section id. Back-fill must leave it untagged — the section
    // is orphaned (download started, parent header rejected/not yet
    // applied).
    let orphan_id = [0xFFu8; 32];
    store.store_block_section(&orphan_id, &[0; 64]).unwrap();

    let n = store.back_fill_modifier_type_index().unwrap();
    assert_eq!(n, 0);
    assert_eq!(store.get_modifier_type(&orphan_id).unwrap(), None);
}

/// Once the sentinel is set, subsequent runs short-circuit without
/// scanning HEADERS — emit only `Start` then `Skipped`.
///
/// The sentinel is only written after a populated successful pass — a
/// fresh-DB run does NOT set it (so a node that boots into an empty DB
/// won't lock out future back-fill against later legacy writes).
#[test]
fn sentinel_present_short_circuits_with_skipped_event() {
    let (_d, store) = temp_store();

    // Populated first run: header + untagged section. This drives the
    // streaming path to completion and writes the sentinel.
    let h0 = [0xE0u8; 32];
    let h0_bytes = write_minimal_header([0xDF; 32], [0xA0; 32], [0xB0; 32], [0xC0; 32]);
    store.store_header(&h0, &h0_bytes).unwrap();
    let h0_tx = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &h0, &[0xB0; 32]);
    store.store_block_section(&h0_tx, &[0; 64]).unwrap();
    let n1 = store.back_fill_modifier_type_index().unwrap();
    assert_eq!(n1, 1, "populated run must tag the one untagged section");

    // Add data AFTER the sentinel — back-fill must not touch it. New
    // sections that arrive after the sentinel are tagged at write time
    // by `store_block_section_typed`; back-fill is a one-shot migration.
    let header_id = [0xEEu8; 32];
    let header_bytes = write_minimal_header([0xE1; 32], [0xE2; 32], [0xE3; 32], [0xE4; 32]);
    store.store_header(&header_id, &header_bytes).unwrap();
    let tx_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &[0xE3; 32]);
    store.store_block_section(&tx_id, &[0; 64]).unwrap();

    let mut events: Vec<ModifierIndexBackfillEvent> = Vec::new();
    let n2 = store
        .back_fill_modifier_type_index_with_progress(|ev| events.push(ev))
        .unwrap();
    assert_eq!(n2, 0);
    assert_eq!(events.len(), 2, "got: {events:?}");
    assert!(matches!(events[0], ModifierIndexBackfillEvent::Start));
    assert!(matches!(events[1], ModifierIndexBackfillEvent::Skipped));

    // Section that arrived after sentinel-set is intentionally untagged.
    assert_eq!(store.get_modifier_type(&tx_id).unwrap(), None);
}

/// Empty-DB run must NOT write the sentinel. Otherwise a fresh node's
/// first boot would lock out any future back-fill against legacy untyped
/// `store_block_section` writes that arrive between boots.
#[test]
fn empty_db_run_does_not_set_sentinel() {
    let (_d, store) = temp_store();

    // First call on empty DB returns 0 and does NOT write sentinel.
    let n1 = store.back_fill_modifier_type_index().unwrap();
    assert_eq!(n1, 0);

    // Now add a header + untagged section. The next back-fill run must
    // NOT see the sentinel (it shouldn't have been written) — it must
    // perform the full scan and tag the new section.
    let header_id = [0x80u8; 32];
    let header_bytes = write_minimal_header([0x7F; 32], [0xA0; 32], [0xB0; 32], [0xC0; 32]);
    store.store_header(&header_id, &header_bytes).unwrap();
    let tx_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &[0xB0; 32]);
    store.store_block_section(&tx_id, &[0; 64]).unwrap();

    let mut events: Vec<ModifierIndexBackfillEvent> = Vec::new();
    let n2 = store
        .back_fill_modifier_type_index_with_progress(|ev| events.push(ev))
        .unwrap();
    assert_eq!(n2, 1, "second run must tag the new section");
    assert_eq!(events.len(), 4, "full lifecycle, not Skipped fast-path");
    assert!(matches!(events[0], ModifierIndexBackfillEvent::Start));
    assert!(matches!(
        events[1],
        ModifierIndexBackfillEvent::AfterCollect { .. }
    ));
    assert_eq!(store.get_modifier_type(&tx_id).unwrap(), Some(102));
}

/// Sentinel must persist across reopen — it lives in `STATE_META` and is
/// committed at `Immediate` durability, so a fresh `StateStore` over the
/// same redb file picks it up and skips the scan.
#[test]
fn sentinel_persists_across_store_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");

    {
        let store = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
        let header_id = [0x91u8; 32];
        let header_bytes = write_minimal_header([0x90; 32], [0xA9; 32], [0xB9; 32], [0xC9; 32]);
        store.store_header(&header_id, &header_bytes).unwrap();
        let tx_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &[0xB9; 32]);
        store.store_block_section(&tx_id, &[0; 64]).unwrap();

        // Real run: drives the full streaming path + final sentinel commit.
        let n = store.back_fill_modifier_type_index().unwrap();
        assert_eq!(n, 1);
        assert_eq!(store.get_modifier_type(&tx_id).unwrap(), Some(102));
    }

    // Drop the first store, reopen the file, run again — sentinel hit.
    let store2 = StateStore::open_with_cache(&path, 4 * 1024 * 1024).unwrap();
    let mut events: Vec<ModifierIndexBackfillEvent> = Vec::new();
    let n = store2
        .back_fill_modifier_type_index_with_progress(|ev| events.push(ev))
        .unwrap();
    assert_eq!(n, 0);
    assert_eq!(events.len(), 2, "got: {events:?}");
    assert!(matches!(events[0], ModifierIndexBackfillEvent::Start));
    assert!(matches!(events[1], ModifierIndexBackfillEvent::Skipped));
}

/// Force the chunked entry point with `bytes_budget=1, rows_cap=1` so a
/// 5-header fixture exercises five separate read/write txn pairs and the
/// `Bound::Excluded(last_seen_id)` cursor restart. Per-chunk events are
/// not emitted: the lifecycle stays Start → AfterCollect → BeforeCommit
/// → AfterCommit regardless of chunk count.
#[test]
fn streaming_processes_multiple_chunks_idempotent() {
    let (_d, store) = temp_store();
    for i in 0u8..5 {
        let hid = [0x40 + i; 32];
        let ad = [0xA4 + i; 32];
        let tx = [0xB4 + i; 32];
        let ext = [0xC4 + i; 32];
        let bytes = write_minimal_header([0x3F + i; 32], ad, tx, ext);
        store.store_header(&hid, &bytes).unwrap();
        let tx_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &hid, &tx);
        store.store_block_section(&tx_id, &[0; 64]).unwrap();
    }

    let mut events: Vec<ModifierIndexBackfillEvent> = Vec::new();
    let written = store
        .back_fill_modifier_type_index_chunked(1, 1, |ev| events.push(ev))
        .unwrap();
    // 5 sections newly tagged (header rows were already tagged by
    // store_header at write time, so they don't count toward `written`).
    assert_eq!(written, 5);
    assert_eq!(
        events.len(),
        4,
        "per-chunk events are not emitted; got: {events:?}"
    );
    match events[1] {
        ModifierIndexBackfillEvent::AfterCollect {
            rows,
            capacity_rows,
            ..
        } => {
            assert_eq!(rows, 5);
            assert_eq!(capacity_rows, 1, "capacity_rows reflects the test cap");
        }
        ref other => panic!("events[1] must be AfterCollect, got {other:?}"),
    }
    if let ModifierIndexBackfillEvent::BeforeCommit { rows } = events[2] {
        assert_eq!(rows, 5, "all 5 rows scanned across the 5 chunks");
    } else {
        panic!("events[2] must be BeforeCommit");
    }

    for i in 0u8..5 {
        let hid = [0x40 + i; 32];
        let tx = [0xB4 + i; 32];
        let tx_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &hid, &tx);
        assert_eq!(store.get_modifier_type(&tx_id).unwrap(), Some(102));
    }

    // Idempotent: a second multi-chunk run hits the sentinel.
    let mut events2: Vec<ModifierIndexBackfillEvent> = Vec::new();
    let n2 = store
        .back_fill_modifier_type_index_chunked(1, 1, |ev| events2.push(ev))
        .unwrap();
    assert_eq!(n2, 0);
    assert_eq!(events2.len(), 2);
    assert!(matches!(events2[1], ModifierIndexBackfillEvent::Skipped));
}

/// Mixed pre-population: some sections pre-tagged via the typed path,
/// others stored via the legacy untagged path. Back-fill must only write
/// the missing entries — the pre-tagged section stays its original type.
#[test]
fn partial_pre_population_completes_remainder() {
    let (_d, store) = temp_store();

    let header_id = [0x71u8; 32];
    let parent = [0x70u8; 32];
    let ad_root = [0xA7u8; 32];
    let tx_root = [0xB7u8; 32];
    let ext_root = [0xC7u8; 32];
    let header_bytes = write_minimal_header(parent, ad_root, tx_root, ext_root);
    store.store_header(&header_id, &header_bytes).unwrap();

    let tx_id = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &tx_root);
    let ad_id = compute_section_id(TYPE_AD_PROOFS, &header_id, &ad_root);
    let ext_id = compute_section_id(TYPE_EXTENSION, &header_id, &ext_root);

    store
        .store_block_section_typed(&tx_id, &[0; 64], 102)
        .unwrap();
    store.store_block_section(&ad_id, &[0; 64]).unwrap();
    store.store_block_section(&ext_id, &[0; 64]).unwrap();

    assert_eq!(store.get_modifier_type(&tx_id).unwrap(), Some(102));
    assert_eq!(store.get_modifier_type(&ad_id).unwrap(), None);
    assert_eq!(store.get_modifier_type(&ext_id).unwrap(), None);

    let n = store.back_fill_modifier_type_index().unwrap();
    assert_eq!(n, 2, "only the two untagged sections must be written");
    assert_eq!(store.get_modifier_type(&tx_id).unwrap(), Some(102));
    assert_eq!(store.get_modifier_type(&ad_id).unwrap(), Some(104));
    assert_eq!(store.get_modifier_type(&ext_id).unwrap(), Some(108));
}

/// A header whose bytes don't deserialize must not abort the chunk: the
/// streaming `read_header` path handles the `Err` with `continue`. The
/// header itself stays tagged 101 (set by `store_header` at write time).
/// Surrounding valid headers' sections must still be tagged in the same
/// scan.
#[test]
fn malformed_header_does_not_abort_remaining_rows() {
    let (_d, store) = temp_store();

    let valid1_id = [0x51u8; 32];
    let valid1_bytes = write_minimal_header([0x50; 32], [0xA5; 32], [0xB5; 32], [0xC5; 32]);
    store.store_header(&valid1_id, &valid1_bytes).unwrap();
    let v1_tx = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &valid1_id, &[0xB5; 32]);
    store.store_block_section(&v1_tx, &[0; 64]).unwrap();

    let bad_id = [0x52u8; 32];
    store
        .store_header(&bad_id, &[0xFF, 0xFF, 0xFF, 0xFF])
        .unwrap();

    let valid2_id = [0x53u8; 32];
    let valid2_bytes = write_minimal_header([0x52; 32], [0xA6; 32], [0xB6; 32], [0xC6; 32]);
    store.store_header(&valid2_id, &valid2_bytes).unwrap();
    let v2_tx = compute_section_id(TYPE_BLOCK_TRANSACTIONS, &valid2_id, &[0xB6; 32]);
    store.store_block_section(&v2_tx, &[0; 64]).unwrap();

    let n = store.back_fill_modifier_type_index().unwrap();
    assert_eq!(n, 2, "valid headers must complete around the malformed one");

    assert_eq!(store.get_modifier_type(&v1_tx).unwrap(), Some(102));
    assert_eq!(store.get_modifier_type(&v2_tx).unwrap(), Some(102));
    // Header rows are tagged by store_header at write time, regardless
    // of body parseability.
    assert_eq!(store.get_modifier_type(&bad_id).unwrap(), Some(101));
}
