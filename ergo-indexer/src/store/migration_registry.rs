//! Ordered schema steps shared by indexer open and the legacy file upgrader.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use redb::{Database, ReadableDatabase};

use super::{meta, migration, INDEXER_SCHEMA_VERSION};
use crate::error::IndexerError;

#[derive(Clone, Copy)]
pub(super) struct MigrationStep {
    pub from: u32,
    pub to: u32,
    pub name: &'static str,
    // Each step owns one atomic transaction, checks cancellation before commit,
    // and writes its fixed `to` version last, in that same transaction.
    pub apply: fn(&Database, &AtomicBool) -> Result<(), IndexerError>,
}

pub(super) const MIGRATIONS: &[MigrationStep] = &[MigrationStep {
    from: 2,
    to: 3,
    name: "repair token metadata and wrapped-script templates",
    apply: migration::migrate_cancellable,
}];

fn valid_registry(steps: &[MigrationStep]) -> bool {
    !steps.is_empty()
        && steps
            .iter()
            .all(|step| step.from.checked_add(1) == Some(step.to))
        && steps.windows(2).all(|pair| pair[0].to == pair[1].from)
        && steps
            .last()
            .is_some_and(|step| step.to == INDEXER_SCHEMA_VERSION)
}

pub(super) fn path_from(steps: &[MigrationStep], from: u32) -> Option<&[MigrationStep]> {
    debug_assert!(valid_registry(steps), "invalid indexer migration registry");
    let start = steps.iter().position(|step| step.from == from)?;
    Some(&steps[start..])
}

/// Whether a persisted schema has registered steps to the current schema.
/// The current schema itself needs no migration and returns false.
pub fn has_migration_path(from: u32) -> bool {
    path_from(MIGRATIONS, from).is_some()
}

pub(super) fn run_uncancelled(db: &Database) -> Result<(), IndexerError> {
    run(db, &AtomicBool::new(false), MIGRATIONS)
}

pub(super) fn run(
    db: &Database,
    cancel: &AtomicBool,
    registry: &[MigrationStep],
) -> Result<(), IndexerError> {
    let version =
        meta::read_schema_version(&db.begin_read()?)?.ok_or(IndexerError::SchemaCorruption)?;
    if version == INDEXER_SCHEMA_VERSION {
        return Ok(());
    }
    let steps = path_from(registry, version).ok_or(IndexerError::SchemaCorruption)?;
    for step in steps {
        if cancel.load(Ordering::Acquire) {
            return Err(IndexerError::MigrationCancelled);
        }
        let start = Instant::now();
        tracing::info!(
            event = "indexer_schema_step_started",
            name = step.name,
            from = step.from,
            to = step.to,
            "starting indexer schema step"
        );
        let result = (step.apply)(db, cancel);
        tracing::info!(
            event = "indexer_schema_step_finished",
            name = step.name,
            from = step.from,
            to = step.to,
            elapsed_secs = start.elapsed().as_secs_f64(),
            success = result.is_ok(),
            "finished indexer schema step"
        );
        result?;
        if meta::read_schema_version(&db.begin_read()?)? != Some(step.to) {
            return Err(IndexerError::SchemaCorruption);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
