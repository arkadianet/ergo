//! Schema 2 → 3 projection repair. One writer publishes all changes together.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ergo_primitives::{digest::Digest32, reader::VlqReader, writer::VlqWriter};
use ergo_ser::opcode::Expr;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};

use super::tables::{
    INDEXED_BOX, INDEXED_TEMPLATE, INDEXED_TOKEN, INDEXER_UNDO, NUMERIC_BOX, SEGMENTS,
};
use super::{meta, segment::read_spill_in, template::read_template_in, INDEXER_SCHEMA_VERSION};
use crate::error::IndexerError;
use crate::rebuild::{read_box, read_box_id};
use crate::segment_buffer::{append_box_entry, flip_box_segment_entry, flush_staged_spills};
use crate::segment_id::box_segment_id;
use crate::template::{flush_templates, template_hash_for_box_bytes, IndexedTemplate};
use crate::token::{
    decode_decimals_r6, decode_description_r5, decode_name_r4, read_indexed_token,
    write_indexed_token,
};

fn invalid(detail: impl Into<String>) -> IndexerError {
    IndexerError::SegmentTopologyError {
        detail: format!("schema-2 migration: {}", detail.into()),
    }
}

pub(crate) fn migrate_cancellable(
    db: &redb::Database,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<(), IndexerError> {
    migrate_cancellable_observed(db, cancel, &mut || Ok(()))
}

fn migrate_cancellable_observed(
    db: &redb::Database,
    cancel: &std::sync::atomic::AtomicBool,
    observer: &mut impl FnMut() -> Result<(), IndexerError>,
) -> Result<(), IndexerError> {
    migrate_controlled(
        db,
        &|| {
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                Err(IndexerError::MigrationCancelled)
            } else {
                Ok(())
            }
        },
        observer,
    )
}

pub(super) fn migrate_schema_2_to_3(db: &redb::Database) -> Result<(), IndexerError> {
    migrate_controlled(db, &|| Ok(()), &mut || Ok(()))
}

#[cfg(test)]
fn migrate_observed(
    db: &redb::Database,
    observer: &mut impl FnMut() -> Result<(), IndexerError>,
) -> Result<(), IndexerError> {
    migrate_controlled(db, &|| Ok(()), observer)
}

// Checks run throughout the transaction; the observer injects faults after writes.
fn migrate_controlled(
    db: &redb::Database,
    check: &(impl Fn() -> Result<(), IndexerError> + Sync),
    observer: &mut impl FnMut() -> Result<(), IndexerError>,
) -> Result<(), IndexerError> {
    check()?;
    let start = Instant::now();
    let mut last_log = start;
    let mut write = ergo_state::begin_write_qr(db)?;
    write.set_durability(redb::Durability::Immediate)?;
    let read = db.begin_read()?;
    let checkpoint = meta::read_meta(&read)?;
    tracing::info!(
        event = "indexer_schema_migration_started",
        boxes = checkpoint.global_box_index,
        height = checkpoint.indexed_height,
        "migrating schema-2 index in place"
    );
    let mut changed_tokens = 0_u64;
    let mut scanned_tokens = 0_u64;
    {
        let old_tokens = read.open_table(INDEXED_TOKEN)?;
        let boxes = read.open_table(INDEXED_BOX)?;
        let mut tokens = write.open_table(INDEXED_TOKEN)?;
        let mut writer = VlqWriter::new();
        for row in old_tokens.iter()? {
            check()?;
            let (key, value) = row?;
            let mut reader = VlqReader::new(value.value());
            let mut token =
                read_indexed_token(&mut reader).map_err(|source| IndexerError::DbDecode {
                    context: "migration_token",
                    source,
                })?;
            if !reader.is_empty() {
                return Err(invalid("trailing bytes in token row"));
            }
            let box_id = token
                .creating_box_id
                .ok_or_else(|| invalid("token has no issuing box"))?;
            let issuing_box = read_box(&boxes, &box_id, 0)?;
            let regs = issuing_box.box_data.candidate.additional_registers();
            let name = Some(decode_name_r4(regs));
            let description = Some(decode_description_r5(regs));
            let decimals = Some(decode_decimals_r6(regs));
            if (
                token.name.as_ref(),
                token.description.as_ref(),
                token.decimals,
            ) != (name.as_ref(), description.as_ref(), decimals)
            {
                token.name = name;
                token.description = description;
                token.decimals = decimals;
                crate::apply::write_then_insert(&mut tokens, &mut writer, key.value(), |w| {
                    write_indexed_token(w, &token);
                    Ok(())
                })?;
                changed_tokens += 1;
                observer()?;
            }
            scanned_tokens += 1;
            if last_log.elapsed() >= Duration::from_secs(10) {
                tracing::info!(
                    event = "indexer_schema_migration_progress",
                    phase = "tokens",
                    scanned_tokens,
                    changed_tokens,
                    elapsed_secs = start.elapsed().as_secs_f64(),
                    "schema-2 migration progress"
                );
                last_log = Instant::now();
            }
        }
    }
    tracing::info!(
        event = "indexer_schema_migration_tokens_complete",
        scanned_tokens,
        changed_tokens,
        elapsed_secs = start.elapsed().as_secs_f64(),
        "token metadata migration complete"
    );

    // Only newly keyable boxes are retained in memory. Existing entries are
    // merged from the old snapshot one spill at a time, including when a wrapped
    // tree shares its v3 key with an already-indexed structured tree.
    let mut additions: HashMap<Digest32, Vec<i64>> = HashMap::new();
    let mut affected_boxes = 0_u64;
    {
        let numeric = read.open_table(NUMERIC_BOX)?;
        let boxes = read.open_table(INDEXED_BOX)?;
        if numeric.len()? != checkpoint.global_box_index
            || boxes.len()? != checkpoint.global_box_index
        {
            return Err(invalid("box counts differ from checkpoint"));
        }
        for gi in 0..checkpoint.global_box_index {
            check()?;
            let box_id = read_box_id(&numeric, gi)?
                .ok_or_else(|| invalid(format!("missing global box index {gi}")))?;
            let record = read_box(&boxes, &box_id, gi)?;
            let index = i64::try_from(gi).map_err(|_| invalid("box index exceeds i64"))?;
            if record.global_index != index {
                return Err(invalid(format!("box global index differs at {gi}")));
            }
            let candidate = &record.box_data.candidate;
            // The v2 received-bytes derivation omitted a whole-tree wrap.
            // Use the box's already-parsed tree, avoiding a second parse of
            // every ordinary tree during this tens-of-millions-row scan.
            if matches!(candidate.ergo_tree().body, Expr::Unparsed(_)) {
                let hash = template_hash_for_box_bytes(candidate.ergo_tree_bytes())?
                    .ok_or_else(|| invalid("wrapped tree has no v3 template key"))?;
                additions
                    .entry(hash)
                    .or_default()
                    .push(if record.is_spent() { -index } else { index });
                affected_boxes += 1;
            }
            if last_log.elapsed() >= Duration::from_secs(10) {
                tracing::info!(
                    event = "indexer_schema_migration_progress",
                    phase = "boxes",
                    scanned_boxes = gi + 1,
                    total_boxes = checkpoint.global_box_index,
                    affected_boxes,
                    changed_tokens,
                    elapsed_secs = start.elapsed().as_secs_f64(),
                    "schema-2 migration progress"
                );
                last_log = Instant::now();
            }
        }
    }
    let affected_templates = additions.len();
    {
        let mut templates = write.open_table(INDEXED_TEMPLATE)?;
        let mut segments = write.open_table(SEGMENTS)?;
        let mut writer = VlqWriter::new();
        let mut staged = HashMap::new();
        let deleted = HashSet::new();
        for (template_number, (hash, new_entries)) in additions.into_iter().enumerate() {
            let old =
                read_template_in(&read, &hash)?.unwrap_or_else(|| IndexedTemplate::empty(hash));
            if old.segment.box_segment_count < 0
                || !old.segment.txs.is_empty()
                || old.segment.tx_segment_count != 0
            {
                return Err(invalid("invalid template segment counters"));
            }
            let mut rebuilt = IndexedTemplate::empty(hash);
            let mut new = new_entries.into_iter().peekable();
            let mut previous = None;
            for spill in 0..=old.segment.box_segment_count {
                check()?;
                let entries = if spill == old.segment.box_segment_count {
                    old.segment.boxes.clone()
                } else {
                    read_spill_in(&read, &box_segment_id(&hash, spill))?
                        .ok_or_else(|| invalid("missing template spill"))?
                        .boxes
                };
                for entry in entries {
                    let index = entry
                        .checked_abs()
                        .ok_or_else(|| invalid("invalid signed box index"))?;
                    if previous.is_some_and(|prev| prev >= index) {
                        return Err(invalid("unordered template entries"));
                    }
                    previous = Some(index);
                    while new.peek().is_some_and(|n| n.abs() < index) {
                        append_signed(
                            &mut rebuilt,
                            new.next().expect("peeked entry"),
                            &mut staged,
                            &segments,
                        )?;
                    }
                    if new.peek().is_some_and(|n| n.abs() == index) {
                        return Err(invalid("wrapped box already present in schema-2 template"));
                    }
                    append_signed(&mut rebuilt, entry, &mut staged, &segments)?;
                }
                flush_staged_spills(&mut segments, &mut writer, &staged, &deleted)?;
                staged.clear();
                if last_log.elapsed() >= Duration::from_secs(10) {
                    tracing::info!(
                        event = "indexer_schema_migration_progress",
                        phase = "templates",
                        completed_templates = template_number,
                        affected_templates,
                        affected_boxes,
                        elapsed_secs = start.elapsed().as_secs_f64(),
                        "schema-2 migration progress"
                    );
                    last_log = Instant::now();
                }
            }
            for entry in new {
                check()?;
                append_signed(&mut rebuilt, entry, &mut staged, &segments)?;
                if !staged.is_empty() {
                    flush_staged_spills(&mut segments, &mut writer, &staged, &deleted)?;
                    staged.clear();
                }
            }
            flush_templates(
                &mut templates,
                &mut writer,
                &HashMap::from([(hash, rebuilt)]),
            )?;
            observer()?;
        }
    }
    // UndoEntry contains ONLY prior checkpoint pointers, never projection
    // deltas. Rollback re-derives template hashes from the supplied block bytes
    // using v3, so the existing entries are already identical to a fresh v3
    // index. Validate all retained entries; neither regeneration nor access to
    // historical chain blocks is needed (including wrapped outputs in-window).
    let undo = read.open_table(INDEXER_UNDO)?;
    for row in undo.iter()? {
        check()?;
        super::UndoEntry::decode(row?.1.value())?;
    }
    observer()?;
    let undo_entries = undo.len()?;
    meta::write_schema_version(&write, INDEXER_SCHEMA_VERSION)?;
    check()?;
    write.commit()?;
    tracing::info!(
        event = "indexer_schema_migration_complete",
        changed_tokens,
        scanned_tokens,
        scanned_boxes = checkpoint.global_box_index,
        affected_boxes,
        affected_templates,
        undo_entries,
        elapsed_secs = start.elapsed().as_secs_f64(),
        "schema-2 index migration committed"
    );
    Ok(())
}

fn append_signed(
    template: &mut IndexedTemplate,
    entry: i64,
    staged: &mut crate::segment_buffer::StagedSpills,
    segments: &redb::Table<&[u8], &[u8]>,
) -> Result<(), IndexerError> {
    let index = entry
        .checked_abs()
        .ok_or_else(|| invalid("invalid signed box index"))?;
    append_box_entry(
        &template.template_hash,
        &mut template.segment,
        index,
        staged,
    )?;
    if entry < 0 {
        flip_box_segment_entry(
            &template.template_hash,
            &mut template.segment,
            index,
            staged,
            segments,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
