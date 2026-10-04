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

/// Bound unfinished queue work: queued or conflicted records and their signed
/// bytes. Finished records never count, so lifetime use cannot fill the queue.
pub const MAX_PRIVATE_TRANSACTIONS: usize = 1024;
const MAX_PRIVATE_BYTES: usize = 16 * 1024 * 1024;
/// Mined transactions keep their signed bytes and input reservations while a
/// rollback could still return them, until they are deeper than the node's
/// rollback window. Beyond these bounds the oldest confirmations release
/// their bytes early instead of blocking new admissions.
const MAX_RECOVERABLE_MINED: usize = MAX_PRIVATE_TRANSACTIONS;
const MAX_RECOVERABLE_MINED_BYTES: usize = MAX_PRIVATE_BYTES;
/// Finished records (cancelled, expired, or settled confirmations) are kept as
/// tombstones without signed bytes or input ids, for idempotent resubmission
/// and rollback of a confirmation. The oldest are forgotten first.
const MAX_FINISHED_RECORDS: usize = 1024;
/// Cursor-only progress is written at most once per this many blocks; after
/// a restart the queue re-reads at most this much applied history.
const CURSOR_PERSIST_INTERVAL: u32 = 32;
/// Startup refuses larger files. Pending and recoverable mined bytes are each
/// bounded by `MAX_PRIVATE_BYTES` and cost about four JSON characters per
/// signed byte together with their hex input ids; per-record metadata of at
/// most `2 * MAX_PRIVATE_TRANSACTIONS + MAX_FINISHED_RECORDS` records fits in
/// the remainder.
const MAX_FILE_BYTES: usize = 9 * MAX_PRIVATE_BYTES;

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

    /// Unfinished work that counts against the queue bounds.
    pub fn is_pending(self) -> bool {
        matches!(self, Self::Queued | Self::InCandidate | Self::Conflicted)
    }

    /// Mined and conflicted transactions can return after rollback. Holding
    /// their original input ids closes the interval before chain catch-up;
    /// spent inputs are absent from ordinary wallet selection anyway. A
    /// confirmation deeper than the rollback window keeps no input ids.
    pub fn reserves_inputs(self) -> bool {
        !matches!(self, Self::Cancelled | Self::Expired)
    }
}

/// Outcome of [`PrivateTransactionQueue::reconcile`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Some record changed state or released its signed bytes.
    pub changed: bool,
    /// Confirmations that released their signed bytes. This node will not
    /// mine them again, so public admission no longer needs to decline them.
    pub released: Vec<String>,
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
    /// Hex signed bytes while this node may still mine the transaction:
    /// pending, or mined within the rollback window. `None` for a tombstone.
    #[serde(default)]
    signed_bytes: Option<String>,
    /// Cancelled or Expired state a confirmation overrode. A rollback of that
    /// confirmation restores it instead of queueing withdrawn work again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    withdrawn: Option<PrivateTransactionState>,
    /// When the record became a tombstone; the oldest is forgotten first.
    #[serde(default)]
    finished_seq: u64,
}

impl Record {
    fn signed_len(&self) -> usize {
        self.signed_bytes.as_ref().map_or(0, |hex| hex.len() / 2)
    }

    /// Drop the signed bytes and input ids of work this node will not mine.
    fn release(&mut self, finished_seq: u64) {
        self.signed_bytes = None;
        self.entry.input_ids.clear();
        self.finished_seq = finished_seq;
    }

    /// Undo a confirmation whose block left the applied chain: withdrawn work
    /// returns to its withdrawn state, anything else waits in the queue again.
    fn unconfirm(&mut self) {
        let e = &mut self.entry;
        e.mined_height = None;
        e.mined_block_id = None;
        match self.withdrawn.take() {
            Some(state) => {
                e.state = state;
                e.reason = Some(withdrawal_reason(state).into());
            }
            // Released bytes cannot be mined again by this node.
            None if self.signed_bytes.is_none() => {
                e.state = PrivateTransactionState::Expired;
                e.reason =
                    Some("mined block rolled back after its signed bytes were released".into());
            }
            None => {
                e.state = PrivateTransactionState::Queued;
                e.reason = Some("mined block rolled back; confirming applied history".into());
            }
        }
    }
}

fn withdrawal_reason(state: PrivateTransactionState) -> &'static str {
    if state == PrivateTransactionState::Cancelled {
        "cancelled by operator"
    } else {
        "local mining deadline elapsed"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Store {
    version: u32,
    records: BTreeMap<String, Record>,
    revision: u64,
    /// Last applied height inspected for confirmation, persisted for restart.
    observed_height: u32,
    observed_tip: Option<String>,
    /// Source of `Record::finished_seq`.
    #[serde(default)]
    finished_seq: u64,
    /// Cursor height last written to disk (runtime only).
    #[serde(skip)]
    persisted_height: u32,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            records: BTreeMap::new(),
            revision: 0,
            observed_height: 0,
            observed_tip: None,
            finished_seq: 0,
            persisted_height: 0,
        }
    }
}

impl Store {
    /// Withdraw pending work: it keeps no signed bytes or input reservation.
    fn finish(&mut self, tx_id: &str, state: PrivateTransactionState) {
        self.finished_seq += 1;
        let finished_seq = self.finished_seq;
        if let Some(record) = self.records.get_mut(tx_id) {
            record.entry.state = state;
            record.entry.reason = Some(withdrawal_reason(state).into());
            record.release(finished_seq);
        }
    }

    /// Release the signed bytes of confirmations deeper than the rollback
    /// window, then of the oldest confirmations beyond the recoverable
    /// bounds. Returns the released ids.
    fn release_settled(&mut self, height: u32, rollback_window: u32) -> Vec<String> {
        let mut mined: Vec<(u32, String, usize)> = self
            .records
            .values()
            .filter(|r| r.entry.state == PrivateTransactionState::Mined && r.signed_bytes.is_some())
            .map(|r| {
                let h = r.entry.mined_height.unwrap_or(0);
                (h, r.entry.tx_id.clone(), r.signed_len())
            })
            .collect();
        // Newest confirmations first: they are the most likely to roll back.
        mined.sort_by(|a, b| b.cmp(a));
        let mut kept_bytes = 0usize;
        let mut released = Vec::new();
        for (kept, (mined_height, tx_id, bytes)) in mined.into_iter().enumerate() {
            kept_bytes = kept_bytes.saturating_add(bytes);
            let settled = height.saturating_sub(mined_height) >= rollback_window;
            if settled || kept >= MAX_RECOVERABLE_MINED || kept_bytes > MAX_RECOVERABLE_MINED_BYTES
            {
                released.push(tx_id);
            }
        }
        for tx_id in &released {
            self.finished_seq += 1;
            let finished_seq = self.finished_seq;
            if let Some(record) = self.records.get_mut(tx_id) {
                record.release(finished_seq);
            }
        }
        released
    }

    /// Keep at most `MAX_FINISHED_RECORDS` tombstones, forgetting the oldest.
    fn forget_oldest_finished(&mut self) {
        let mut finished: Vec<(u64, String)> = self
            .records
            .values()
            .filter(|r| r.signed_bytes.is_none())
            .map(|r| (r.finished_seq, r.entry.tx_id.clone()))
            .collect();
        if finished.len() <= MAX_FINISHED_RECORDS {
            return;
        }
        finished.sort();
        let excess = finished.len() - MAX_FINISHED_RECORDS;
        for (_, tx_id) in finished.into_iter().take(excess) {
            self.records.remove(&tx_id);
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
        sweep_temporaries(&path);
        let store = match std::fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() > MAX_FILE_BYTES {
                    return Err("private queue file exceeds its bounded size".into());
                }
                let mut store: Store = serde_json::from_slice(&bytes)
                    .map_err(|_| "private queue file is invalid".to_string())?;
                if store.version != 1
                    || store.records.len() > 2 * MAX_PRIVATE_TRANSACTIONS + MAX_FINISHED_RECORDS
                {
                    return Err("private queue version or record count is unsupported".into());
                }
                for record in store.records.values() {
                    if record.signed_bytes.is_some() {
                        materialize(record)?;
                    } else if record.entry.state.is_pending() {
                        return Err("private queue pending record has no signed bytes".into());
                    }
                }
                store.persisted_height = store.observed_height;
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

    /// Ids this node may still mine privately (records that keep signed
    /// bytes); public admission must decline them.
    pub fn guarded_ids(&self) -> Vec<[u8; 32]> {
        self.lock()
            .records
            .values()
            .filter(|r| r.signed_bytes.is_some())
            .filter_map(|r| decode_id(&r.entry.tx_id).ok())
            .collect()
    }

    /// Inputs stay reserved across restart, conflict, and rollback until an
    /// explicit cancellation or expiry withdraws the transaction permanently.
    pub fn reserved_inputs(&self) -> BTreeSet<[u8; 32]> {
        self.lock()
            .records
            .values()
            .filter(|r| r.entry.state.reserves_inputs())
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
        self.admit_at_tip(entry, options, now_ms, tip_height, None)
    }

    /// Persist the initial applied branch identity with the first admission,
    /// including if the process stops before its next lifecycle tick.
    pub fn admit_at_tip(
        &self,
        entry: &Entry,
        options: PrivateTransactionOptions,
        now_ms: u64,
        tip_height: u32,
        tip_id: Option<String>,
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
            if record.entry.state.is_pending()
                || record.entry.state == PrivateTransactionState::Mined
            {
                return Ok(record.entry.clone());
            }
            // A cancelled or expired id may be queued again as a fresh item.
        }
        let pending = || {
            store
                .records
                .values()
                .filter(|r| r.entry.state.is_pending())
        };
        if pending().count() >= MAX_PRIVATE_TRANSACTIONS {
            return Err("private transaction queue is full".into());
        }
        let bytes: usize = pending().map(Record::signed_len).sum();
        if bytes.saturating_add(entry.bytes.len()) > MAX_PRIVATE_BYTES {
            return Err("private transaction queue byte budget exhausted".into());
        }
        let input_ids: Vec<String> = entry
            .inputs
            .iter()
            .map(|id| hex::encode(id.as_bytes()))
            .collect();
        if store.records.values().any(|r| {
            r.entry.state.reserves_inputs()
                && r.entry.input_ids.iter().any(|id| input_ids.contains(id))
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
            updated.observed_tip = tip_id;
        }
        updated.records.insert(
            tx_id,
            Record {
                entry: result.clone(),
                signed_bytes: Some(hex::encode(&entry.bytes)),
                withdrawn: None,
                finished_seq: 0,
            },
        );
        self.commit(&mut store, updated)?;
        Ok(result)
    }

    /// Withdraw pending work. Repeating a cancellation is idempotent.
    pub fn cancel(&self, tx_id: &str) -> Result<PrivateTransactionEntry, String> {
        let mut store = self.lock();
        let record = store
            .records
            .get(tx_id)
            .ok_or("private transaction not found")?;
        if record.entry.state == PrivateTransactionState::Mined {
            return Err("a confirmed transaction cannot be cancelled".into());
        }
        if !record.entry.state.is_pending() {
            return Ok(record.entry.clone());
        }
        let mut updated = store.clone();
        updated.finish(tx_id, PrivateTransactionState::Cancelled);
        updated.forget_oldest_finished();
        let result = updated.records[tx_id].entry.clone();
        self.commit(&mut store, updated)?;
        Ok(result)
    }

    /// Deadlines withdraw pending work; they never broadcast the transaction.
    /// Returns the ids that expired.
    pub fn expire(&self, now_ms: u64, parent_height: u32) -> Result<Vec<String>, String> {
        let mut store = self.lock();
        let expired: Vec<String> = store
            .records
            .values()
            .filter(|r| {
                r.entry.state.is_pending()
                    && (r.entry.expires_at_ms.is_some_and(|d| d <= now_ms)
                        || r.entry
                            .expires_at_height
                            .is_some_and(|d| d <= parent_height))
            })
            .map(|r| r.entry.tx_id.clone())
            .collect();
        if expired.is_empty() {
            return Ok(expired);
        }
        let mut updated = store.clone();
        for tx_id in &expired {
            updated.finish(tx_id, PrivateTransactionState::Expired);
        }
        updated.forget_oldest_finished();
        self.commit(&mut store, updated)?;
        Ok(expired)
    }

    pub fn observation_cursor(&self) -> (u32, Option<String>) {
        let store = self.lock();
        (store.observed_height, store.observed_tip.clone())
    }

    /// Reopen definitely orphaned confirmations before bounded ancestry work.
    /// The cursor is untouched so exact applied confirmations still catch up.
    pub fn reopen_rolled_back(&self, tx_ids: &BTreeSet<String>) -> Result<bool, String> {
        if tx_ids.is_empty() {
            return Ok(false);
        }
        let mut store = self.lock();
        if !tx_ids.iter().any(|id| {
            store
                .records
                .get(id)
                .is_some_and(|r| r.entry.state == PrivateTransactionState::Mined)
        }) {
            return Ok(false);
        }
        let mut updated = store.clone();
        for id in tx_ids {
            if let Some(record) = updated.records.get_mut(id) {
                if record.entry.state == PrivateTransactionState::Mined {
                    record.unconfirm();
                }
            }
        }
        self.commit(&mut store, updated)?;
        Ok(true)
    }

    /// Record incremental ancestry progress during a deep rollback. Kept in
    /// memory: a restart repeats the bounded walk from the persisted cursor.
    pub fn set_observation_cursor(&self, height: u32, tip: Option<String>) {
        let mut store = self.lock();
        store.observed_height = height;
        store.observed_tip = tip;
    }

    /// Reconcile exact applied transactions and canonical mined-block identity.
    /// Missing inputs can recover after a rollback; cancellation/expiry cannot.
    /// Confirmations deeper than `rollback_window` release their signed bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile(
        &self,
        height: u32,
        tip_id: String,
        applied: &BTreeMap<String, (u32, String)>,
        canonical: impl Fn(u32, &str) -> bool,
        input_available: impl Fn(&[u8; 32]) -> bool,
        candidate_ids: &BTreeSet<String>,
        rollback_window: u32,
    ) -> Result<Reconciled, String> {
        let mut store = self.lock();
        let mut updated = store.clone();
        let mut changed = false;
        for record in updated.records.values_mut() {
            let previous = record.entry.state;
            if let Some((h, id)) = applied.get(&record.entry.tx_id) {
                // A confirmation wins over any local state: a deadline or a
                // cancellation that raced the block must not hide that the
                // transaction was mined.
                if matches!(
                    previous,
                    PrivateTransactionState::Cancelled | PrivateTransactionState::Expired
                ) {
                    record.withdrawn = Some(previous);
                }
                let e = &mut record.entry;
                changed |= e.mined_height != Some(*h) || e.mined_block_id.as_ref() != Some(id);
                e.state = PrivateTransactionState::Mined;
                e.mined_height = Some(*h);
                e.mined_block_id = Some(id.clone());
                e.reason = None;
                changed |= previous != e.state;
                continue;
            }
            if matches!(
                previous,
                PrivateTransactionState::Cancelled | PrivateTransactionState::Expired
            ) {
                continue;
            }
            let e = &mut record.entry;
            if e.mined_height
                .zip(e.mined_block_id.as_deref())
                .is_some_and(|(h, id)| canonical(h, id))
            {
                e.state = PrivateTransactionState::Mined;
            } else if record.withdrawn.is_some() || record.signed_bytes.is_none() {
                // Its confirmation left the applied chain, but this node will
                // not mine it again.
                record.unconfirm();
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
            changed |= previous != record.entry.state;
        }
        let released = updated.release_settled(height, rollback_window);
        if !released.is_empty() {
            updated.forget_oldest_finished();
            changed = true;
        }
        updated.observed_height = height;
        updated.observed_tip = Some(tip_id);
        if changed {
            self.commit(&mut store, updated)?;
        } else if height
            >= store
                .persisted_height
                .saturating_add(CURSOR_PERSIST_INTERVAL)
        {
            // Cursor-only progress is written in bounded steps; between them
            // a restart re-reads at most CURSOR_PERSIST_INTERVAL blocks.
            self.persist(&updated)?;
            updated.persisted_height = height;
            *store = updated;
        } else {
            store.observed_height = updated.observed_height;
            store.observed_tip = updated.observed_tip;
        }
        Ok(Reconciled { changed, released })
    }

    /// Persist a changed store, then make it current. On failure nothing
    /// changes, so reservations and pending work survive a failed write.
    fn commit(&self, store: &mut Store, mut updated: Store) -> Result<(), String> {
        updated.revision = updated.revision.wrapping_add(1);
        self.persist(&updated)?;
        updated.persisted_height = updated.observed_height;
        *store = updated;
        Ok(())
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
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let bytes = serde_json::to_vec(store).map_err(|_| "private queue serialization failed")?;
        // Create exclusively so stale files or symlinks cannot redirect a
        // write containing private transaction bytes. A random name never
        // repeats across restarts; retry the rare collision with a fresh one.
        let mut attempt = 0;
        let (tmp, mut file) = loop {
            let tmp = temporary_path(path);
            match options.open(&tmp) {
                Ok(file) => break (tmp, file),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 3 => {
                    attempt += 1;
                }
                Err(e) => return Err(format!("private queue temporary file: {e}")),
            }
        };
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

/// A temporary name that cannot repeat across restarts, even when a container
/// gives the node the same process id every time. `RandomState` keys come from
/// the operating system's random source.
fn temporary_path(path: &Path) -> PathBuf {
    use std::hash::{BuildHasher, Hasher};
    static WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed));
    path.with_extension(format!("{:016x}.tmp", hasher.finish()))
}

/// Remove temporaries left by an interrupted write; they can hold signed
/// bytes. Best effort: a leftover never blocks a later write, whose name is
/// random. Matches only `<queue stem>.<anything>.tmp` in the queue directory.
fn sweep_temporaries(path: &Path) {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return;
    };
    let prefix = format!("{stem}.");
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let stale = name.len() > prefix.len() + ".tmp".len()
            && name.starts_with(&prefix)
            && name.ends_with(".tmp");
        // `file_type` does not follow links, so a link is removed, never its target.
        if stale && entry.file_type().is_ok_and(|kind| !kind.is_dir()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn decode_id(id: &str) -> Result<[u8; 32], String> {
    hex::decode(id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "private queue has an invalid identifier".into())
}

fn materialize(record: &Record) -> Result<Entry, String> {
    let signed = record
        .signed_bytes
        .as_deref()
        .ok_or("private queue record has no signed bytes")?;
    let bytes = hex::decode(signed).map_err(|_| "private queue has invalid transaction bytes")?;
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
