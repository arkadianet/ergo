//! Durable operator transactions kept entirely outside the public mempool.
//!
//! Bytes here never participate in relay inventory, peer retrieval, public
//! mempool projections, or mempool revalidation. Admission and candidate
//! assembly still validate them against the normal consensus context.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ergo_mempool::pool::Entry;
use ergo_mempool::types::TxSource;
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::transaction::{read_transaction, transaction_id};
use serde::{Deserialize, Serialize};

/// Bound persistent queue work and the size of each atomic rewrite.
pub const MAX_PRIVATE_TRANSACTIONS: usize = 1024;
const MAX_PRIVATE_BYTES: usize = 16 * 1024 * 1024;

/// Operator policy for one transaction. Expiry is a local queue deadline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTransactionOptions {
    pub expires_at_ms: Option<u64>,
    pub expires_at_height: Option<u32>,
    pub priority: i32,
    pub label: Option<String>,
}

/// Lifecycle retained across process restart and chain rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTransactionState {
    Queued,
    InCandidate,
    Mined,
    Conflicted,
    Cancelled,
    Expired,
}

impl PrivateTransactionState {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Queued | Self::InCandidate)
    }
}

/// Owner-only metadata. Signed bytes intentionally have a separate record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateTransactionEntry {
    pub tx_id: String,
    pub state: PrivateTransactionState,
    pub reason: Option<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub expires_at_height: Option<u32>,
    pub priority: i32,
    pub label: Option<String>,
    pub input_ids: Vec<String>,
    pub fee_nano_erg: String,
    pub size_bytes: u32,
    pub validation_cost: u64,
    pub mined_block_id: Option<String>,
    pub mined_height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    entry: PrivateTransactionEntry,
    signed_bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Store {
    version: u32,
    records: BTreeMap<String, Record>,
    revision: u64,
    /// Last applied height inspected for confirmation, persisted for restart.
    observed_height: u32,
    observed_tip: Option<String>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            records: BTreeMap::new(),
            revision: 0,
            observed_height: 0,
            observed_tip: None,
        }
    }
}

/// Single durable collection shared with the wallet and mining handle.
#[derive(Debug, Default)]
pub struct PrivateTransactionQueue {
    path: Option<PathBuf>,
    store: Mutex<Store>,
}

impl PrivateTransactionQueue {
    /// Open the node-owned private file; malformed state fails startup closed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let store = match std::fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() > MAX_PRIVATE_BYTES * 3 {
                    return Err("private queue file exceeds its bounded size".into());
                }
                let store: Store = serde_json::from_slice(&bytes)
                    .map_err(|_| "private queue file is invalid".to_string())?;
                if store.version != 1 || store.records.len() > MAX_PRIVATE_TRANSACTIONS {
                    return Err("private queue version or record count is unsupported".into());
                }
                for record in store.records.values() {
                    materialize(record)?;
                }
                store
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Store::default(),
            Err(e) => return Err(format!("cannot read private queue: {e}")),
        };
        Ok(Self {
            path: Some(path),
            store: Mutex::new(store),
        })
    }

    pub fn revision(&self) -> u64 {
        self.lock().revision
    }

    pub fn list(&self) -> Vec<PrivateTransactionEntry> {
        self.lock()
            .records
            .values()
            .map(|r| r.entry.clone())
            .collect()
    }

    pub fn entry(&self, tx_id: &str) -> Option<PrivateTransactionEntry> {
        self.lock().records.get(tx_id).map(|r| r.entry.clone())
    }

    /// Active inputs are reserved even before a candidate has included them.
    pub fn reserved_inputs(&self) -> BTreeSet<[u8; 32]> {
        self.lock()
            .records
            .values()
            .filter(|r| r.entry.state.is_active())
            .flat_map(|r| &r.entry.input_ids)
            .filter_map(|id| decode_id(id).ok())
            .collect()
    }

    /// Rebuilt on load, and always revalidated during candidate assembly.
    pub fn selection_entries(&self) -> Vec<Entry> {
        self.selection_entries_at(0, 0)
    }

    /// Filter deadlines even if the durable expiry transition fails. This
    /// keeps failed persistence from reintroducing withdrawn work in a build.
    pub fn selection_entries_at(&self, now_ms: u64, parent_height: u32) -> Vec<Entry> {
        let store = self.lock();
        let mut records: Vec<_> = store
            .records
            .values()
            .filter(|r| {
                r.entry.state.is_active()
                    && r.entry.expires_at_ms.is_none_or(|d| d > now_ms)
                    && r.entry.expires_at_height.is_none_or(|d| d > parent_height)
            })
            .collect();
        records.sort_by(|a, b| {
            b.entry
                .priority
                .cmp(&a.entry.priority)
                .then(a.entry.created_at_ms.cmp(&b.entry.created_at_ms))
                .then(a.entry.tx_id.cmp(&b.entry.tx_id))
        });
        records
            .into_iter()
            .filter_map(|r| materialize(r).ok())
            .collect()
    }

    /// Commit only after normal transaction validation has succeeded.
    pub fn admit(
        &self,
        entry: &Entry,
        options: PrivateTransactionOptions,
        now_ms: u64,
        tip_height: u32,
    ) -> Result<PrivateTransactionEntry, String> {
        if options
            .expires_at_ms
            .is_some_and(|deadline| deadline <= now_ms)
        {
            return Err("private transaction deadline has already elapsed".into());
        }
        if options
            .expires_at_height
            .is_some_and(|height| height <= tip_height)
        {
            return Err("private transaction height deadline has already elapsed".into());
        }
        if options.label.as_ref().is_some_and(|s| s.len() > 200) {
            return Err("private transaction label exceeds 200 bytes".into());
        }
        let mut store = self.lock();
        let tx_id = hex::encode(entry.tx_id.as_bytes());
        if let Some(record) = store.records.get(&tx_id) {
            if record.entry.state.is_active()
                || record.entry.state == PrivateTransactionState::Mined
            {
                return Ok(record.entry.clone());
            }
            return Err("transaction has already been cancelled, expired, or conflicted".into());
        }
        if store.records.len() >= MAX_PRIVATE_TRANSACTIONS {
            return Err("private transaction queue is full".into());
        }
        let bytes: usize = store
            .records
            .values()
            .map(|r| r.signed_bytes.len() / 2)
            .sum();
        if bytes.saturating_add(entry.bytes.len()) > MAX_PRIVATE_BYTES {
            return Err("private transaction queue byte budget exhausted".into());
        }
        let input_ids: Vec<String> = entry
            .inputs
            .iter()
            .map(|id| hex::encode(id.as_bytes()))
            .collect();
        if store.records.values().any(|r| {
            r.entry.state.is_active() && r.entry.input_ids.iter().any(|id| input_ids.contains(id))
        }) {
            return Err("an input is already reserved by another private transaction".into());
        }
        let result = PrivateTransactionEntry {
            tx_id: tx_id.clone(),
            state: PrivateTransactionState::Queued,
            reason: None,
            created_at_ms: now_ms,
            expires_at_ms: options.expires_at_ms,
            expires_at_height: options.expires_at_height,
            priority: options.priority,
            label: options.label,
            input_ids,
            fee_nano_erg: entry.fee.to_string(),
            size_bytes: entry.size_bytes,
            validation_cost: entry.cost,
            mined_block_id: None,
            mined_height: None,
        };
        let mut updated = store.clone();
        if updated.records.is_empty() {
            updated.observed_height = tip_height;
        }
        updated.records.insert(
            tx_id,
            Record {
                entry: result.clone(),
                signed_bytes: hex::encode(&entry.bytes),
            },
        );
        updated.revision = updated.revision.wrapping_add(1);
        self.persist(&updated)?;
        *store = updated;
        Ok(result)
    }

    pub fn cancel(&self, tx_id: &str) -> Result<PrivateTransactionEntry, String> {
        self.update(|store| {
            let record = store
                .records
                .get_mut(tx_id)
                .ok_or("private transaction not found")?;
            if record.entry.state == PrivateTransactionState::Mined {
                return Err("a confirmed transaction cannot be cancelled".into());
            }
            if record.entry.state.is_active()
                || record.entry.state == PrivateTransactionState::Conflicted
            {
                record.entry.state = PrivateTransactionState::Cancelled;
                record.entry.reason = Some("cancelled by operator".into());
            }
            Ok(record.entry.clone())
        })
    }

    /// Deadlines withdraw pending work; they never broadcast the transaction.
    pub fn expire(&self, now_ms: u64, parent_height: u32) -> Result<bool, String> {
        let mut store = self.lock();
        let mut updated = store.clone();
        let mut changed = false;
        for r in updated.records.values_mut() {
            if matches!(
                r.entry.state,
                PrivateTransactionState::Queued
                    | PrivateTransactionState::InCandidate
                    | PrivateTransactionState::Conflicted
            ) && (r.entry.expires_at_ms.is_some_and(|d| d <= now_ms)
                || r.entry
                    .expires_at_height
                    .is_some_and(|d| d <= parent_height))
            {
                r.entry.state = PrivateTransactionState::Expired;
                r.entry.reason = Some("local mining deadline elapsed".into());
                changed = true;
            }
        }
        if changed {
            updated.revision = updated.revision.wrapping_add(1);
            self.persist(&updated)?;
            *store = updated;
        }
        Ok(changed)
    }

    pub fn observation_cursor(&self) -> (u32, Option<String>) {
        let store = self.lock();
        (store.observed_height, store.observed_tip.clone())
    }

    /// Persist incremental ancestry progress during a deep rollback.
    pub fn set_observation_cursor(&self, height: u32, tip: Option<String>) -> Result<(), String> {
        self.update(|store| {
            store.observed_height = height;
            store.observed_tip = tip;
            Ok(())
        })
    }

    /// Reconcile exact applied transactions and canonical mined-block identity.
    /// Missing inputs can recover after a rollback; cancellation/expiry cannot.
    pub fn reconcile(
        &self,
        height: u32,
        tip_id: String,
        applied: &BTreeMap<String, (u32, String)>,
        canonical: impl Fn(u32, &str) -> bool,
        input_available: impl Fn(&[u8; 32]) -> bool,
        candidate_ids: &BTreeSet<String>,
    ) -> Result<bool, String> {
        let mut store = self.lock();
        let mut updated = store.clone();
        let mut changed = false;
        for record in updated.records.values_mut() {
            let e = &mut record.entry;
            if matches!(
                e.state,
                PrivateTransactionState::Cancelled | PrivateTransactionState::Expired
            ) {
                continue;
            }
            let previous = e.state;
            if let Some((h, id)) = applied.get(&e.tx_id) {
                e.state = PrivateTransactionState::Mined;
                e.mined_height = Some(*h);
                e.mined_block_id = Some(id.clone());
                e.reason = None;
            } else if e
                .mined_height
                .zip(e.mined_block_id.as_deref())
                .is_some_and(|(h, id)| canonical(h, id))
            {
                e.state = PrivateTransactionState::Mined;
            } else {
                e.mined_height = None;
                e.mined_block_id = None;
                let available = e
                    .input_ids
                    .iter()
                    .all(|id| decode_id(id).is_ok_and(|id| input_available(&id)));
                if !available {
                    e.state = PrivateTransactionState::Conflicted;
                    e.reason =
                        Some("one or more inputs are unavailable on the applied chain".into());
                } else {
                    e.state = if candidate_ids.contains(&e.tx_id) {
                        PrivateTransactionState::InCandidate
                    } else {
                        PrivateTransactionState::Queued
                    };
                    e.reason = None;
                }
            }
            changed |= previous != e.state;
        }
        let cursor_changed =
            updated.observed_height != height || updated.observed_tip.as_deref() != Some(&tip_id);
        updated.observed_height = height;
        updated.observed_tip = Some(tip_id);
        if changed || cursor_changed {
            updated.revision = updated.revision.wrapping_add(u64::from(changed));
            self.persist(&updated)?;
            *store = updated;
        }
        Ok(changed)
    }

    fn update<T>(&self, f: impl FnOnce(&mut Store) -> Result<T, String>) -> Result<T, String> {
        let mut store = self.lock();
        let mut updated = store.clone();
        let result = f(&mut updated)?;
        updated.revision = updated.revision.wrapping_add(1);
        self.persist(&updated)?;
        *store = updated;
        Ok(result)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn persist(&self, store: &Store) -> Result<(), String> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let parent = path
            .parent()
            .ok_or("private queue path needs a directory")?;
        std::fs::create_dir_all(parent).map_err(|e| format!("private queue directory: {e}"))?;
        static WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let tmp = path.with_extension(format!(
            "{}.{}.tmp",
            std::process::id(),
            WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let bytes = serde_json::to_vec(store).map_err(|_| "private queue serialization failed")?;
        // Create exclusively so stale files or symlinks cannot redirect a
        // write containing private transaction bytes.
        let mut file = options
            .open(&tmp)
            .map_err(|e| format!("private queue temporary file: {e}"))?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&tmp, path)?;
            #[cfg(unix)]
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.map_err(|e: std::io::Error| format!("private queue commit failed: {e}"))
    }
}

fn decode_id(id: &str) -> Result<[u8; 32], String> {
    hex::decode(id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "private queue has an invalid identifier".into())
}

fn materialize(record: &Record) -> Result<Entry, String> {
    let bytes = hex::decode(&record.signed_bytes)
        .map_err(|_| "private queue has invalid transaction bytes")?;
    let mut reader = VlqReader::new(&bytes);
    let tx =
        read_transaction(&mut reader).map_err(|_| "private queue transaction cannot be decoded")?;
    if !reader.is_empty() {
        return Err("private queue transaction has trailing bytes".into());
    }
    let id = transaction_id(&tx).map_err(|_| "private queue transaction identifier failed")?;
    if hex::encode(id.as_bytes()) != record.entry.tx_id {
        return Err("private queue transaction identifier mismatch".into());
    }
    let input_ids: Vec<_> = tx
        .inputs
        .iter()
        .map(|i| hex::encode(i.box_id.as_bytes()))
        .collect();
    if input_ids != record.entry.input_ids || bytes.len() != record.entry.size_bytes as usize {
        return Err("private queue transaction metadata mismatch".into());
    }
    let output_boxes: Vec<_> = tx
        .output_candidates
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| ergo_ser::ergo_box::ErgoBox {
            candidate,
            transaction_id: id,
            index: index as u16,
        })
        .collect();
    let outputs = output_boxes
        .iter()
        .map(|b| {
            b.box_id()
                .map_err(|_| "private queue output identifier failed".to_string())
        })
        .collect::<Result<_, _>>()?;
    Ok(Entry::new(
        Digest32::from_bytes(*id.as_bytes()),
        Arc::from(bytes),
        tx.inputs.into_iter().map(|i| i.box_id).collect(),
        outputs,
        vec![],
        record
            .entry
            .fee_nano_erg
            .parse()
            .map_err(|_| "private queue fee is invalid")?,
        0,
        record.entry.size_bytes,
        record.entry.validation_cost,
        TxSource::Wallet,
    )
    .with_output_boxes(output_boxes))
}

#[cfg(test)]
mod tests;
