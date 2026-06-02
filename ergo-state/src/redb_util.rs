//! redb write-transaction helper.
//!
//! Every production write transaction MUST go through [`begin_write_qr`]
//! rather than calling `db.begin_write()` directly. The helper sets
//! `quick_repair = true` on the transaction so that, after an unclean
//! shutdown (`kill -9`, OS crash, power loss), the next `Database::open`
//! finds the allocator state already serialized and skips the
//! O(file-size) repair walk.
//!
//! Quick-repair is non-monotonic: a single commit that omits the flag
//! leaves the database needing full repair on the next dirty open,
//! defeating the purpose for every preceding quick-repair commit. The
//! audit rule is therefore mechanical — `grep "db.begin_write()"` over
//! production code should return zero results; every site goes through
//! this helper.
//!
//! Test code is held to the same rule for uniformity — the quick-repair
//! flag is set on every redb commit, production and test alike. The
//! ~5µs per-commit overhead is negligible against test setup costs.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use redb::{Database, DatabaseError, TransactionError, WriteTransaction};
use tracing::info;

/// Open a redb write transaction with quick-repair enabled.
///
/// See module docs for the non-monotonicity contract.
#[allow(clippy::result_large_err)] // redb's TransactionError shape is fixed upstream
pub fn begin_write_qr(db: &Database) -> Result<WriteTransaction, TransactionError> {
    let mut txn = db.begin_write()?;
    txn.set_quick_repair(true);
    Ok(txn)
}

/// Open (or create) a redb database at `path`, emitting structured
/// `redb_repair_*` events whenever the post-unclean-shutdown repair
/// walk runs.
///
/// `db_name` is the journal-event identifier (`"state"`, `"indexer"`,
/// `"address_book"`, ...). It is emitted verbatim in the `db` field so
/// operators can filter dashboards by subsystem.
///
/// Events:
///
/// - `redb_repair_started` — fires on the first progress callback. Repair
///   was actually needed (i.e. the previous shutdown was unclean and
///   `set_quick_repair` was not on every commit).
/// - `redb_repair_progress` — fires on each subsequent callback. Useful
///   when the repair takes minutes on a large DB.
/// - `redb_repair_complete` — fires after `create(path)` returns, *only*
///   if the start event fired. Includes `elapsed_ms` so an operator can
///   see how long the repair took.
///
/// On a clean reopen redb's `Drop` ensures allocator state and the
/// callback never fires, so no events are emitted. This is the
/// expected path post-`begin_write_qr` adoption (see module docs).
#[allow(clippy::result_large_err)] // redb's DatabaseError shape is fixed upstream
pub fn open_with_repair_logging(
    path: &Path,
    db_name: &'static str,
) -> Result<Database, DatabaseError> {
    let repair_started = Arc::new(AtomicBool::new(false));
    let cb_started = repair_started.clone();
    let cb_path = path.display().to_string();

    let t0 = Instant::now();
    let db = Database::builder()
        .set_repair_callback(move |session| {
            let was_started = cb_started.swap(true, Ordering::SeqCst);
            let pct = session.progress() * 100.0;
            if !was_started {
                info!(
                    event = "redb_repair_started",
                    db = db_name,
                    path = %cb_path,
                    progress_pct = pct,
                    "redb repair started",
                );
            } else {
                info!(
                    event = "redb_repair_progress",
                    db = db_name,
                    path = %cb_path,
                    progress_pct = pct,
                    "redb repair progress",
                );
            }
        })
        .create(path)?;

    if repair_started.load(Ordering::SeqCst) {
        info!(
            event = "redb_repair_complete",
            db = db_name,
            path = %path.display(),
            elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0,
            "redb repair complete",
        );
    }

    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::TableDefinition;
    use tempfile::tempdir;

    // Observability note: redb 2.6.3 does not expose a getter for the
    // quick-repair flag on `WriteTransaction`, and `Database::drop`
    // itself ensures allocator state on graceful close — so this test
    // can only verify that the helper returns a usable txn that
    // commits, not that quick-repair is *effective* on an unclean
    // shutdown. The latter requires a subprocess + kill -9 harness
    // (not built here). This test is a regression catcher for "did
    // someone break the helper signature or wiring", which is what
    // 80+ call sites depend on.

    // ----- happy path -----

    #[test]
    fn begin_write_qr_returns_usable_txn_and_commits() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("qr_smoke.redb");
        let db = Database::create(&path).unwrap();

        let table: TableDefinition<&str, &[u8]> = TableDefinition::new("t");
        let txn = begin_write_qr(&db).unwrap();
        {
            let mut t = txn.open_table(table).unwrap();
            t.insert("k", b"v".as_slice()).unwrap();
        }
        txn.commit().unwrap();

        let read_txn = db.begin_read().unwrap();
        let t = read_txn.open_table(table).unwrap();
        let got = t.get("k").unwrap().unwrap();
        assert_eq!(got.value(), b"v");
    }

    // ----- round-trips -----

    #[test]
    fn begin_write_qr_round_trips_through_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("qr_reopen.redb");
        let table: TableDefinition<&str, &[u8]> = TableDefinition::new("t");

        {
            let db = Database::create(&path).unwrap();
            let txn = begin_write_qr(&db).unwrap();
            {
                let mut t = txn.open_table(table).unwrap();
                t.insert("persisted", b"yes".as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        // Graceful close above; reopen and verify. Repair callback
        // must not fire — graceful close always leaves a valid
        // allocator state table in redb 2.6.3, helper or not.
        let callback_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cb = callback_fired.clone();
        let db = redb::Builder::new()
            .set_repair_callback(move |_| {
                cb.store(true, std::sync::atomic::Ordering::SeqCst);
            })
            .create(&path)
            .unwrap();
        assert!(
            !callback_fired.load(std::sync::atomic::Ordering::SeqCst),
            "repair callback fired on graceful reopen — open path broken"
        );

        let read_txn = db.begin_read().unwrap();
        let t = read_txn.open_table(table).unwrap();
        let got = t.get("persisted").unwrap().unwrap();
        assert_eq!(got.value(), b"yes");
    }
}
