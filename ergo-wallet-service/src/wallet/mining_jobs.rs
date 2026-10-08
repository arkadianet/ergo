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
}

fn invalid(reason: impl Into<String>) -> WalletStoreError {
    WalletStoreError::decode(reason)
}

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
