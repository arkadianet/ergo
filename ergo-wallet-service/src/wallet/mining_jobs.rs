//! Offline checks and recoverable quarantine for the wallet job journal.
//! Records remain opaque here apart from the lifecycle state; the wallet engine owns
//! their complete schema and the pinned input reservations inside each record.

use super::WalletStoreError;
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition};
use serde::Deserialize;

pub const META: TableDefinition<&str, u64> = TableDefinition::new("wallet_mining_jobs_meta_v1");

pub const JOURNAL: TableDefinition<u64, &[u8]> = TableDefinition::new("wallet_mining_jobs_v1");
pub const QUARANTINE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("wallet_mining_jobs_quarantined_v1");

#[derive(Deserialize)]
struct RecordState {
    job: JobState,
}

#[derive(Deserialize)]
struct JobState {
    state: String,
    #[serde(default, rename = "txId")]
    tx_id: Option<String>,
}

fn invalid(reason: impl Into<String>) -> WalletStoreError {
    WalletStoreError::decode(reason)
}

/// Jobs still owned by the scheduler, including terminal transactions followed
/// through reorgs. These can be resubmitted when their private entry disappears.
pub fn pending_jobs(txn: &ReadTransaction) -> Result<Vec<u64>, WalletStoreError> {
    let table = match txn.open_table(JOURNAL) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut pending = Vec::new();
    for (count, row) in table.iter()?.enumerate() {
        let (id, value) = row?;
        if count >= 256 || value.value().len() > 512 * 1024 {
            return Err(invalid("job journal bounds exceeded"));
        }
        let record: RecordState =
            serde_json::from_slice(value.value()).map_err(|error| invalid(error.to_string()))?;
        match record.job.state.as_str() {
            "waiting" | "waitingForWallet" | "preparing" | "prepared" | "queued"
            | "inCandidate" => pending.push(id.value()),
            "mined" | "conflicted" if record.job.tx_id.is_some() => pending.push(id.value()),
            "mined" | "conflicted" | "cancelled" | "expired" | "failed" => {}
            state => return Err(invalid(format!("unknown wallet job state {state:?}"))),
        }
    }
    Ok(pending)
}

/// Preserve complete records, including signed bytes, outside the table the
/// scheduler reads. Also quarantine terminal jobs that could follow a queue
/// transaction through a later rollback. The monotonic ID counter stays intact.
pub fn quarantine(db: &Database) -> Result<u64, WalletStoreError> {
    let read = super::store::read_redb(db)?;
    pending_jobs(&read)?;
    let table = match read.open_table(JOURNAL) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut records = Vec::new();
    for row in table.iter()? {
        let (id, value) = row?;
        records.push((id.value(), value.value().to_vec()));
    }
    let txn = super::store::begin_write_quick(db)?;
    {
        let mut saved = txn.open_table(QUARANTINE)?;
        for (id, bytes) in &records {
            if saved.get(*id)?.is_some() {
                return Err(invalid("quarantine already contains this wallet job ID"));
            }
            saved.insert(*id, bytes.as_slice())?;
        }
    }
    txn.open_table(JOURNAL)?.retain(|_, _| false)?;
    txn.commit()?;
    Ok(records.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wallet_protocol::native::dto::WalletJobState;
    use redb::ReadableDatabase;
    use redb::ReadableTableMetadata;

    #[test]
    fn offline_pending_jobs_include_terminal_transaction_followers() {
        use WalletJobState::*;
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("jobs.redb")).unwrap();
        let write = db.begin_write().unwrap();
        {
            let mut journal = write.open_table(JOURNAL).unwrap();
            for (index, (state, tx_id)) in [
                (Waiting, None),
                (Mined, Some("11".repeat(32))),
                (Conflicted, Some("22".repeat(32))),
                (Mined, None),
                (Conflicted, None),
                (Cancelled, Some("33".repeat(32))),
                (Expired, Some("44".repeat(32))),
                (Failed, Some("55".repeat(32))),
            ]
            .into_iter()
            .enumerate()
            {
                let record = serde_json::to_vec(&serde_json::json!({
                    "job": { "state": state, "txId": tx_id }
                }))
                .unwrap();
                journal.insert(index as u64 + 1, record.as_slice()).unwrap();
            }
        }
        write.commit().unwrap();
        assert_eq!(
            pending_jobs(&db.begin_read().unwrap()).unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn colliding_quarantine_id_preserves_the_entire_active_journal() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("jobs.redb")).unwrap();
        let first = br#"{"job":{"state":"mined","txId":"retained-transaction"},"signed_hex":"full-signed-record"}"#;
        let second = br#"{"job":{"state":"queued","txId":"queued-transaction"},"signed_hex":"second-record"}"#;
        let existing = b"previously quarantined approval";
        let write = db.begin_write().unwrap();
        {
            let mut journal = write.open_table(JOURNAL).unwrap();
            journal.insert(1, first.as_slice()).unwrap();
            journal.insert(2, second.as_slice()).unwrap();
        }
        write
            .open_table(QUARANTINE)
            .unwrap()
            .insert(2, existing.as_slice())
            .unwrap();
        write
            .open_table(META)
            .unwrap()
            .insert("next_id", 19)
            .unwrap();
        write.commit().unwrap();
        assert!(quarantine(&db)
            .unwrap_err()
            .to_string()
            .contains("already contains"));
        let read = db.begin_read().unwrap();
        let journal = read.open_table(JOURNAL).unwrap();
        assert_eq!(journal.len().unwrap(), 2);
        assert_eq!(journal.get(1).unwrap().unwrap().value(), first);
        assert_eq!(journal.get(2).unwrap().unwrap().value(), second);
        let saved = read.open_table(QUARANTINE).unwrap();
        assert_eq!(saved.len().unwrap(), 1);
        assert_eq!(saved.get(2).unwrap().unwrap().value(), existing);
        assert_eq!(
            read.open_table(META)
                .unwrap()
                .get("next_id")
                .unwrap()
                .unwrap()
                .value(),
            19
        );
    }
}
