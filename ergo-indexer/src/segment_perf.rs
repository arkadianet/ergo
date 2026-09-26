//! Reproducible historical-spend microbenchmark; never opens node data.
use super::*;
use ergo_primitives::writer::VlqWriter;

thread_local! {
    static SPILL_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn record_spill_read() {
    SPILL_READS.with(|count| count.set(count.get() + 1));
}

fn history(spills: i32) -> (tempfile::TempDir, redb::Database, Digest32, Segment) {
    history_with(spills, |index| index)
}

fn history_with(
    spills: i32,
    value: impl Fn(i64) -> i64,
) -> (tempfile::TempDir, redb::Database, Digest32, Segment) {
    let dir = tempfile::tempdir().unwrap();
    let db = redb::Database::create(dir.path().join("segments.redb")).unwrap();
    let parent = Digest32::from_bytes([0x42; 32]);
    let mut txn = ergo_state::begin_write_qr(&db).unwrap();
    txn.set_durability(redb::Durability::Eventual);
    {
        let mut table = txn.open_table(crate::store::tables::SEGMENTS).unwrap();
        let mut writer = VlqWriter::new();
        for number in 0..spills {
            let first = i64::from(number) * SEGMENT_THRESHOLD as i64 + 1;
            let mut segment = Segment::empty();
            segment.boxes = (first..first + SEGMENT_THRESHOLD as i64)
                .map(&value)
                .collect();
            writer.clear();
            crate::segment::write_segment(&mut writer, &segment);
            let id = box_segment_id(&parent, number);
            table
                .insert(id.as_bytes().as_slice(), writer.as_slice())
                .unwrap();
        }
    }
    txn.commit().unwrap();
    let mut head = Segment::empty();
    head.box_segment_count = spills;
    head.boxes = vec![value(i64::from(spills) * SEGMENT_THRESHOLD as i64 + 1)];
    (dir, db, parent, head)
}

#[test]
fn old_box_lookup_is_bounded_by_segment_depth() {
    let (_dir, db, parent, mut head) = history(4096);
    let txn = ergo_state::begin_write_qr(&db).unwrap();
    let table = txn.open_table(crate::store::tables::SEGMENTS).unwrap();
    let mut staged = StagedSpills::new();
    SPILL_READS.with(|count| count.set(0));
    flip_box_segment_entry(&parent, &mut head, 1, &mut staged, &table).unwrap();
    let reads = SPILL_READS.with(|count| count.get());
    assert!(
        reads <= 14,
        "4096 spills must take logarithmic reads, got {reads}"
    );
    assert_eq!(staged.len(), 1);
}

#[test]
fn ordered_lookup_matches_linear_reference_across_duplicates_gaps_and_rollback() {
    // Three entries per number, with gaps. Duplicates cross spill and head
    // boundaries, including box zero whose sign cannot encode spent state.
    let value = |index: i64| ((index - 1) / 3) * 2;
    let (_dir, db, parent, mut head) = history_with(8, value);
    let mut expected_head = head.boxes.clone();
    let mut expected_spills: Vec<Vec<i64>> = (0..8)
        .map(|spill| {
            let first = spill * SEGMENT_THRESHOLD as i64 + 1;
            (first..first + SEGMENT_THRESHOLD as i64)
                .map(value)
                .collect()
        })
        .collect();
    let mut txn = ergo_state::begin_write_qr(&db).unwrap();
    txn.set_durability(redb::Durability::Eventual);
    let mut table = txn.open_table(crate::store::tables::SEGMENTS).unwrap();
    let mut staged = StagedSpills::new();
    let mut seed = 7u64;
    for target in [
        0,
        2,
        value(512),
        value(513),
        value(4096),
        value(4097),
        i64::MAX,
    ]
    .into_iter()
    .chain((0..80).map(|_| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (seed % 2800) as i64
    })) {
        for apply in [
            true, true, false, true, true, true, false, false, false, false,
        ] {
            let mut present = false;
            let mut flipped = false;
            for entries in
                std::iter::once(&mut expected_head).chain(expected_spills.iter_mut().rev())
            {
                if let Some(entry) = entries.iter_mut().find(|entry| {
                    entry.abs() == target
                        && (target == 0 || if apply { **entry > 0 } else { **entry < 0 })
                }) {
                    *entry = -*entry;
                    flipped = true;
                    break;
                }
                present |= entries.iter().any(|entry| entry.abs() == target);
            }
            let result = if apply {
                flip_box_segment_entry(&parent, &mut head, target, &mut staged, &table)
            } else {
                unflip_box_segment_entry(&parent, &mut head, target, &mut staged, &table)
            };
            assert!(
                match result {
                    Ok(()) => flipped,
                    Err(IndexerError::SegmentTopologyError { .. }) => !flipped && present,
                    Err(IndexerError::SegmentEntryMissing { .. }) => !flipped && !present,
                    other => panic!("unexpected result: {other:?}"),
                },
                "target={target}, apply={apply}"
            );
            assert_eq!(head.boxes, expected_head);
        }
        flush_staged_spills(
            &mut table,
            &mut VlqWriter::new(),
            &staged,
            &DeletedSpills::new(),
        )
        .unwrap();
        staged.clear();
    }
    for (number, expected) in expected_spills.iter().enumerate() {
        let id = box_segment_id(&parent, number as i32);
        assert_eq!(
            &read_spill_from_table(&table, &id).unwrap().unwrap().boxes,
            expected
        );
    }
    drop(table);
    txn.commit().unwrap();
}

#[test]
fn searched_spill_corruption_remains_fatal() {
    for corruption in ["missing", "empty", "unsorted", "minimum", "trailing"] {
        let (_dir, db, parent, mut head) = history(4);
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        let mut table = txn.open_table(crate::store::tables::SEGMENTS).unwrap();
        // Segment 2 is the first binary-search probe.
        let id = box_segment_id(&parent, 2);
        let mut spill = read_spill_from_table(&table, &id).unwrap().unwrap();
        if corruption == "missing" {
            table.remove(id.as_bytes().as_slice()).unwrap();
        } else {
            match corruption {
                "empty" => spill.boxes.clear(),
                "unsorted" => spill.boxes.swap(0, 1),
                "minimum" => spill.boxes[0] = i64::MIN,
                _ => {}
            }
            let mut writer = VlqWriter::new();
            crate::segment::write_segment(&mut writer, &spill);
            if corruption == "trailing" {
                writer.put_u8(0);
            }
            table
                .insert(id.as_bytes().as_slice(), writer.as_slice())
                .unwrap();
        }
        let mut staged = StagedSpills::new();
        let result = flip_box_segment_entry(&parent, &mut head, 1, &mut staged, &table);
        assert!(
            matches!(
                result,
                Err(IndexerError::SegmentTopologyError { .. } | IndexerError::DbRowLength { .. })
            ),
            "{corruption}: {result:?}"
        );
        assert!(staged.is_empty());
    }
}

#[test]
fn spending_old_box_stages_only_changed_spill_and_preserves_other_rows() {
    let (_dir, db, parent, mut head) = history(64);
    let txn = ergo_state::begin_write_qr(&db).unwrap();
    let mut staged = StagedSpills::new();
    let selected_id = box_segment_id(&parent, 0);
    {
        let mut table = txn.open_table(crate::store::tables::SEGMENTS).unwrap();
        let before: Vec<_> = table
            .iter()
            .unwrap()
            .map(|row| {
                let (key, value) = row.unwrap();
                (key.value().to_vec(), value.value().to_vec())
            })
            .collect();
        flip_box_segment_entry(&parent, &mut head, 1, &mut staged, &table).unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[&selected_id].boxes[0], -1);
        // A second operation sees the staged version, not the old disk row.
        assert!(matches!(
            flip_box_segment_entry(&parent, &mut head, 1, &mut staged, &table),
            Err(IndexerError::SegmentTopologyError { .. })
        ));
        flush_staged_spills(
            &mut table,
            &mut VlqWriter::new(),
            &staged,
            &DeletedSpills::new(),
        )
        .unwrap();
        for (key, value) in before {
            if key.as_slice() != selected_id.as_bytes() {
                assert_eq!(table.get(key.as_slice()).unwrap().unwrap().value(), value);
            }
        }
    }
    txn.commit().unwrap();
    // Rollback reads the now-persisted negative entry and changes only it.
    let txn = ergo_state::begin_write_qr(&db).unwrap();
    let table = txn.open_table(crate::store::tables::SEGMENTS).unwrap();
    staged.clear();
    unflip_box_segment_entry(&parent, &mut head, 1, &mut staged, &table).unwrap();
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[&selected_id].boxes[0], 1);
}

/// One warm-up plus five measured samples per case. Reports lookup and
/// flush/commit separately, with the exact number of rows staged for writing.
/// Each sample spends then rolls back the same entry inside a transaction so
/// the next sample sees the same persisted history. No timing assertions.
#[test]
#[ignore = "manual performance measurement; uses an isolated temporary database"]
fn historical_spend_benchmark() {
    for spills in [64, 4096] {
        let (_dir, db, parent, original) = history(spills);
        for (case, target) in [
            ("oldest", 1),
            (
                "middle",
                i64::from(spills / 2) * SEGMENT_THRESHOLD as i64 + 1,
            ),
            ("head", original.boxes[0]),
        ] {
            let mut lookups = Vec::new();
            let mut commits = Vec::new();
            let mut staged_rows = 0;
            for run in 0..6 {
                let mut head = original.clone();
                let mut staged = StagedSpills::new();
                let mut txn = ergo_state::begin_write_qr(&db).unwrap();
                txn.set_durability(redb::Durability::Eventual);
                let lookup_ms;
                let flush_start;
                {
                    let mut table = txn.open_table(crate::store::tables::SEGMENTS).unwrap();
                    let start = std::time::Instant::now();
                    flip_box_segment_entry(&parent, &mut head, target, &mut staged, &table)
                        .unwrap();
                    unflip_box_segment_entry(&parent, &mut head, target, &mut staged, &table)
                        .unwrap();
                    lookup_ms = start.elapsed().as_secs_f64() * 1000.0;
                    staged_rows = staged.len();
                    flush_start = std::time::Instant::now();
                    flush_staged_spills(
                        &mut table,
                        &mut VlqWriter::new(),
                        &staged,
                        &DeletedSpills::new(),
                    )
                    .unwrap();
                }
                txn.commit().unwrap();
                if run > 0 {
                    lookups.push(lookup_ms);
                    commits.push(flush_start.elapsed().as_secs_f64() * 1000.0);
                }
            }
            lookups.sort_by(f64::total_cmp);
            commits.sort_by(f64::total_cmp);
            eprintln!("segment_bench spills={spills} case={case} lookup_pair_ms={:.3} flush_commit_ms={:.3} staged_rows={staged_rows}", lookups[2], commits[2]);
        }
    }
}
