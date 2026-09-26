//! Reproducible historical-spend microbenchmark; never opens node data.
use super::*;
use ergo_primitives::writer::VlqWriter;

fn history(spills: i32) -> (tempfile::TempDir, redb::Database, Digest32, Segment) {
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
            segment.boxes = (first..first + SEGMENT_THRESHOLD as i64).collect();
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
    head.boxes = vec![i64::from(spills) * SEGMENT_THRESHOLD as i64 + 1];
    (dir, db, parent, head)
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
