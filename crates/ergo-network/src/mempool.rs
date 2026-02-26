use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant, SystemTime};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use ergo_types::transaction::{compute_box_id, BoxId, ErgoBoxCandidate, ErgoTransaction, Input, TxId};

/// Compute the blake2b-256 hash of the given data.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).unwrap();
    out
}

/// Well-known ErgoTree bytes for the miners' fee proposition contract.
/// This is the `MINERS_FEE_BASE16_BYTES` from sigma-rust/ergo-lib.
const MINERS_FEE_ERGO_TREE: &[u8] = &[
    0x10, 0x05, 0x04, 0x00, 0x04, 0x00, 0x0e, 0x36, 0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd,
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
    0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
    0xf8, 0x17, 0x98, 0xea, 0x02, 0xd1, 0x92, 0xa3, 0x9a, 0x8c, 0xc7, 0xa7, 0x01, 0x73, 0x00,
    0x73, 0x01, 0x10, 0x01, 0x02, 0x04, 0x02, 0xd1, 0x96, 0x83, 0x03, 0x01, 0x93, 0xa3, 0x8c,
    0xc7, 0xb2, 0xa5, 0x73, 0x00, 0x00, 0x01, 0x93, 0xc2, 0xb2, 0xa5, 0x73, 0x01, 0x00, 0x74,
    0x73, 0x02, 0x73, 0x03, 0x83, 0x01, 0x08, 0xcd, 0xee, 0xac, 0x93, 0xb1, 0xa5, 0x73, 0x04,
];

/// Extract the mining fee from a transaction.
///
/// In Ergo, the fee is an explicit output to the fee proposition contract.
/// Sum all outputs whose ErgoTree matches the miners' fee proposition.
fn extract_fee(tx: &ErgoTransaction) -> u64 {
    tx.output_candidates
        .iter()
        .filter(|out| out.ergo_tree_bytes == MINERS_FEE_ERGO_TREE)
        .map(|out| out.value)
        .sum()
}

/// Compute the weight of a transaction for mempool ordering.
///
/// Weight = (fee * 1024) / tx_size, matching Scala's FeePerByte mode.
/// Returns 0 for zero-fee or zero-size transactions.
fn compute_weight(fee: u64, tx_size: usize) -> u64 {
    if tx_size == 0 {
        return 0;
    }
    fee.saturating_mul(1024) / tx_size as u64
}

/// Key for the ordered mempool index. Sorts by descending weight, then by tx_id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WeightedTxKey {
    neg_weight: i64, // negated weight for descending sort
    tx_id: TxId,
}

impl Ord for WeightedTxKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.neg_weight
            .cmp(&other.neg_weight)
            .then(self.tx_id.0.cmp(&other.tx_id.0))
    }
}

impl PartialOrd for WeightedTxKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Errors that can occur when interacting with the mempool.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("transaction already in pool: {0:?}")]
    AlreadyExists(TxId),
    #[error("double spend: box {0:?} already spent by tx {1:?}")]
    DoubleSpend(BoxId, TxId),
    #[error("pool is full (limit: {0})")]
    PoolFull(usize),
    #[error("transaction too large: {size} bytes (max: {max})")]
    TxTooLarge { size: usize, max: u32 },
    #[error("transaction is blacklisted: {tx_id}")]
    Blacklisted { tx_id: String },
}

/// Validate a transaction for mempool insertion (size + blacklist).
pub fn validate_for_pool(
    tx_size: usize,
    blacklisted_transactions: &[String],
    max_transaction_size: u32,
    tx_id: &TxId,
) -> Result<(), MempoolError> {
    if tx_size > max_transaction_size as usize {
        return Err(MempoolError::TxTooLarge {
            size: tx_size,
            max: max_transaction_size,
        });
    }
    let tx_id_hex = hex::encode(tx_id.0);
    if blacklisted_transactions.iter().any(|b| b == &tx_id_hex) {
        return Err(MempoolError::Blacklisted { tx_id: tx_id_hex });
    }
    Ok(())
}

/// A transaction stored in the mempool together with its insertion timestamp.
struct MempoolEntry {
    tx: ErgoTransaction,
    created_at: Instant,
    created_at_millis: u64,
    tx_size: usize,
    weight: u64,
}

/// Reference to an unconfirmed output in the mempool.
pub struct OutputRef<'a> {
    pub tx_id: TxId,
    pub index: u16,
    pub candidate: &'a ErgoBoxCandidate,
}

/// Reference to a mempool output matched by ErgoTree hash.
pub struct MempoolOutputRef<'a> {
    pub tx_id: TxId,
    pub index: u16,
    pub candidate: &'a ErgoBoxCandidate,
}

/// Basic transaction pool for unconfirmed transactions.
///
/// Tracks which boxes are being spent by which transactions to detect
/// double-spend attempts. Enforces a configurable size limit.
pub struct ErgoMemPool {
    pool: HashMap<TxId, MempoolEntry>,
    input_index: HashMap<BoxId, TxId>,
    ordered: BTreeMap<WeightedTxKey, TxId>,
    size_limit: usize,
}

/// Histogram bin for fee estimation.
pub struct HistogramBin {
    pub n_txns: usize,
    pub total_size: usize,
    pub from_millis: u64,
    pub to_millis: u64,
}

impl ErgoMemPool {
    /// Create a new mempool with the given maximum number of transactions.
    pub fn new(size_limit: usize) -> Self {
        Self {
            pool: HashMap::new(),
            input_index: HashMap::new(),
            ordered: BTreeMap::new(),
            size_limit,
        }
    }

    /// Add a transaction to the pool.
    ///
    /// Returns an error if:
    /// - The pool has reached its size limit ([`MempoolError::PoolFull`])
    /// - A transaction with the same ID already exists ([`MempoolError::AlreadyExists`])
    /// - Any input box is already spent by another pooled transaction
    ///   ([`MempoolError::DoubleSpend`])
    pub fn put(&mut self, tx: ErgoTransaction) -> Result<(), MempoolError> {
        // Check capacity first.
        if self.pool.len() >= self.size_limit {
            return Err(MempoolError::PoolFull(self.size_limit));
        }

        // Reject duplicates.
        if self.pool.contains_key(&tx.tx_id) {
            return Err(MempoolError::AlreadyExists(tx.tx_id));
        }

        // Check every input for double-spend conflicts.
        for input in &tx.inputs {
            if let Some(&existing_tx_id) = self.input_index.get(&input.box_id) {
                return Err(MempoolError::DoubleSpend(input.box_id, existing_tx_id));
            }
        }

        // Index every input box → this tx.
        for input in &tx.inputs {
            self.input_index.insert(input.box_id, tx.tx_id);
        }

        let tx_id = tx.tx_id;
        // No size info available via this path, so weight = 0.
        let key = WeightedTxKey {
            neg_weight: 0,
            tx_id,
        };
        self.ordered.insert(key, tx_id);
        self.pool.insert(tx_id, MempoolEntry {
            tx,
            created_at: Instant::now(),
            created_at_millis: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            tx_size: 0,
            weight: 0,
        });
        Ok(())
    }

    /// Add a transaction to the pool, recording its serialized size.
    ///
    /// Same as `put()` but also stores the byte size for fee estimation.
    pub fn put_with_size(&mut self, tx: ErgoTransaction, tx_size: usize) -> Result<(), MempoolError> {
        if self.pool.contains_key(&tx.tx_id) {
            return Err(MempoolError::AlreadyExists(tx.tx_id));
        }
        for input in &tx.inputs {
            if let Some(&existing_tx_id) = self.input_index.get(&input.box_id) {
                return Err(MempoolError::DoubleSpend(input.box_id, existing_tx_id));
            }
        }

        let fee = extract_fee(&tx);
        let weight = compute_weight(fee, tx_size);

        // If pool is full, try to evict the lowest-priority transaction.
        if self.pool.len() >= self.size_limit {
            if let Some((&victim_key, &victim_id)) = self.ordered.iter().next_back() {
                let victim_weight = (-victim_key.neg_weight) as u64;
                if weight > victim_weight {
                    // New tx has higher priority, evict victim.
                    self.remove(&victim_id);
                } else {
                    return Err(MempoolError::PoolFull(self.size_limit));
                }
            } else {
                return Err(MempoolError::PoolFull(self.size_limit));
            }
        }

        for input in &tx.inputs {
            self.input_index.insert(input.box_id, tx.tx_id);
        }
        let tx_id = tx.tx_id;
        let key = WeightedTxKey {
            neg_weight: -(weight as i64),
            tx_id,
        };
        self.ordered.insert(key, tx_id);
        self.pool.insert(tx_id, MempoolEntry {
            tx,
            created_at: Instant::now(),
            created_at_millis: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            tx_size,
            weight,
        });
        Ok(())
    }

    /// Remove a transaction by ID.
    ///
    /// Returns the removed transaction if it was present, cleaning up all
    /// associated input index entries.
    pub fn remove(&mut self, tx_id: &TxId) -> Option<ErgoTransaction> {
        let entry = self.pool.remove(tx_id)?;
        // Remove from the ordered index.
        let key = WeightedTxKey {
            neg_weight: -(entry.weight as i64),
            tx_id: *tx_id,
        };
        self.ordered.remove(&key);
        for input in &entry.tx.inputs {
            self.input_index.remove(&input.box_id);
        }
        Some(entry.tx)
    }

    /// Remove all transactions from the pool that conflict (double-spend) with
    /// the given transaction.
    ///
    /// For each input of `tx`, if a different pooled transaction spends the
    /// same box, that conflicting transaction is removed.
    pub fn remove_with_double_spends(&mut self, tx: &ErgoTransaction) {
        // Collect conflicting tx IDs first to avoid borrow issues.
        let conflicting_ids: Vec<TxId> = tx
            .inputs
            .iter()
            .filter_map(|input| self.input_index.get(&input.box_id).copied())
            .collect();

        for id in conflicting_ids {
            self.remove(&id);
        }
    }

    /// Remove all transactions from the pool that conflict with a confirmed block.
    ///
    /// For each transaction in the block, removes any pooled transactions
    /// whose inputs overlap with the block's transaction inputs.
    /// Also removes the exact same transaction if it was in the pool.
    pub fn remove_for_block(&mut self, transactions: &[ErgoTransaction]) {
        for tx in transactions {
            self.remove_with_double_spends(tx);
            // Also remove the exact same transaction if it was in the pool.
            self.remove(&tx.tx_id);
        }
    }

    /// Check if a box is already being spent by a pooled transaction.
    pub fn is_double_spend(&self, box_id: &BoxId) -> bool {
        self.input_index.contains_key(box_id)
    }

    /// Get a transaction by ID.
    pub fn get(&self, tx_id: &TxId) -> Option<&ErgoTransaction> {
        self.pool.get(tx_id).map(|entry| &entry.tx)
    }

    /// Return references to all transactions currently in the pool,
    /// ordered by priority (highest fee-per-byte first).
    pub fn get_all(&self) -> Vec<&ErgoTransaction> {
        self.ordered
            .values()
            .filter_map(|tx_id| self.pool.get(tx_id).map(|e| &e.tx))
            .collect()
    }

    /// Get a transaction with its serialized size.
    pub fn get_with_size(&self, tx_id: &TxId) -> Option<(&ErgoTransaction, usize)> {
        self.pool.get(tx_id).map(|e| (&e.tx, e.tx_size))
    }

    /// Return all transactions with their serialized sizes,
    /// ordered by priority (highest fee-per-byte first).
    pub fn get_all_with_size(&self) -> Vec<(&ErgoTransaction, usize)> {
        self.ordered
            .values()
            .filter_map(|tx_id| self.pool.get(tx_id).map(|e| (&e.tx, e.tx_size)))
            .collect()
    }

    /// Current number of transactions in the pool.
    pub fn size(&self) -> usize {
        self.pool.len()
    }

    /// Check if a transaction with the given ID is in the pool.
    pub fn contains(&self, tx_id: &TxId) -> bool {
        self.pool.contains_key(tx_id)
    }

    /// Evict transactions that have been in the pool longer than `max_age`.
    ///
    /// Returns the IDs of all evicted transactions.
    pub fn evict_stale(&mut self, max_age: Duration) -> Vec<TxId> {
        let now = Instant::now();
        let stale_ids: Vec<TxId> = self
            .pool
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.created_at) > max_age)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale_ids {
            self.remove(id);
        }
        stale_ids
    }

    /// Return the IDs of every transaction currently in the pool.
    pub fn get_all_tx_ids(&self) -> Vec<TxId> {
        self.pool.keys().copied().collect()
    }

    /// Find which mempool transaction spends a given box ID.
    /// Returns the spending transaction's ID and a reference to the spending input.
    pub fn find_spending_input(&self, box_id: &BoxId) -> Option<(TxId, &Input)> {
        let tx_id = self.input_index.get(box_id)?;
        let entry = self.pool.get(tx_id)?;
        let input = entry.tx.inputs.iter().find(|inp| inp.box_id == *box_id)?;
        Some((entry.tx.tx_id, input))
    }

    /// Find an unconfirmed output box by its computed box ID.
    pub fn find_output_by_box_id(&self, target: &BoxId) -> Option<OutputRef<'_>> {
        for entry in self.pool.values() {
            for (idx, output) in entry.tx.output_candidates.iter().enumerate() {
                let box_id = compute_box_id(&entry.tx.tx_id, idx as u16);
                if box_id == *target {
                    return Some(OutputRef {
                        tx_id: entry.tx.tx_id,
                        index: idx as u16,
                        candidate: output,
                    });
                }
            }
        }
        None
    }

    /// Find all unconfirmed outputs containing the given token ID.
    pub fn find_outputs_by_token_id(&self, token_id: &BoxId) -> Vec<OutputRef<'_>> {
        let mut results = Vec::new();
        for entry in self.pool.values() {
            for (idx, output) in entry.tx.output_candidates.iter().enumerate() {
                if output.tokens.iter().any(|(tid, _)| tid == token_id) {
                    results.push(OutputRef {
                        tx_id: entry.tx.tx_id,
                        index: idx as u16,
                        candidate: output,
                    });
                }
            }
        }
        results
    }

    /// Check if a box is being spent by any transaction in the mempool.
    pub fn is_spent_in_mempool(&self, box_id: &BoxId) -> bool {
        self.input_index.contains_key(box_id)
    }

    /// Find all unconfirmed outputs whose ErgoTree hash matches `tree_hash`.
    ///
    /// Computes `blake2b256(output.ergo_tree_bytes)` for every output in the
    /// mempool and returns those that match.
    pub fn find_outputs_by_tree_hash(&self, tree_hash: &[u8; 32]) -> Vec<MempoolOutputRef<'_>> {
        let mut results = Vec::new();
        for entry in self.pool.values() {
            for (idx, output) in entry.tx.output_candidates.iter().enumerate() {
                let hash = blake2b256(&output.ergo_tree_bytes);
                if hash == *tree_hash {
                    results.push(MempoolOutputRef {
                        tx_id: entry.tx.tx_id,
                        index: idx as u16,
                        candidate: output,
                    });
                }
            }
        }
        results
    }

    /// Find unconfirmed transactions that have at least one output matching `tree_hash`.
    pub fn find_txs_by_tree_hash(&self, tree_hash: &[u8; 32]) -> Vec<&ErgoTransaction> {
        self.pool
            .values()
            .filter(|entry| {
                entry
                    .tx
                    .output_candidates
                    .iter()
                    .any(|o| blake2b256(&o.ergo_tree_bytes) == *tree_hash)
            })
            .map(|entry| &entry.tx)
            .collect()
    }

    /// Find unconfirmed outputs matching all provided register key-value pairs.
    /// Each entry in `register_filter` is (register_index, expected_bytes).
    pub fn find_outputs_by_registers(
        &self,
        register_filter: &[(u8, Vec<u8>)],
    ) -> Vec<MempoolOutputRef<'_>> {
        let mut results = Vec::new();
        if register_filter.is_empty() {
            return results;
        }
        for entry in self.pool.values() {
            for (idx, output) in entry.tx.output_candidates.iter().enumerate() {
                let all_match = register_filter.iter().all(|(reg_idx, expected)| {
                    output
                        .additional_registers
                        .iter()
                        .any(|(r, val)| *r == *reg_idx && val == expected)
                });
                if all_match {
                    results.push(MempoolOutputRef {
                        tx_id: entry.tx.tx_id,
                        index: idx as u16,
                        candidate: output,
                    });
                }
            }
        }
        results
    }

    /// Re-validate mempool transactions by checking that their input boxes
    /// still exist according to the given predicate.
    ///
    /// Returns IDs of transactions with missing inputs.
    /// Stops after accumulating `cost_limit` of estimated cost.
    pub fn audit_against_utxo<F>(&self, box_exists: F, cost_limit: u64) -> Vec<TxId>
    where
        F: Fn(&BoxId) -> bool,
    {
        let mut invalid = Vec::new();
        let mut accumulated_cost: u64 = 0;
        for entry in self.pool.values() {
            let tx_cost = 10_000u64 + entry.tx.inputs.len() as u64 * 2_000;
            accumulated_cost = accumulated_cost.saturating_add(tx_cost);
            if accumulated_cost > cost_limit {
                break;
            }
            let all_inputs_present = entry.tx.inputs.iter().all(|input| box_exists(&input.box_id));
            if !all_inputs_present {
                invalid.push(entry.tx.tx_id);
            }
        }
        invalid
    }

    /// Remove a batch of transactions by their IDs.
    pub fn remove_batch(&mut self, tx_ids: &[TxId]) {
        for id in tx_ids {
            self.remove(id);
        }
    }

    /// Return cloned copies of all transactions in the pool,
    /// ordered by priority (highest fee-per-byte first).
    ///
    /// Used by mining to get transactions for block assembly without
    /// holding the mempool lock.
    pub fn take_all_cloned(&self) -> Vec<ErgoTransaction> {
        self.ordered
            .values()
            .filter_map(|tx_id| self.pool.get(tx_id).map(|e| e.tx.clone()))
            .collect()
    }

    /// Compute a histogram of mempool transactions binned by wait time.
    ///
    /// `bins` is the number of bins, `max_time_millis` is the total time range.
    /// Each bin covers `max_time_millis / bins` milliseconds of wait time.
    pub fn pool_histogram(&self, bins: usize, max_time_millis: u64) -> Vec<HistogramBin> {
        if bins == 0 {
            return Vec::new();
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let interval = max_time_millis / bins as u64;
        let mut histogram: Vec<HistogramBin> = (0..bins)
            .map(|i| HistogramBin {
                n_txns: 0,
                total_size: 0,
                from_millis: i as u64 * interval,
                to_millis: (i as u64 + 1) * interval,
            })
            .collect();

        for entry in self.pool.values() {
            let wait = now.saturating_sub(entry.created_at_millis);
            let bin_idx = if interval > 0 {
                (wait / interval) as usize
            } else {
                0
            };
            let bin_idx = bin_idx.min(bins - 1);
            histogram[bin_idx].n_txns += 1;
            histogram[bin_idx].total_size += entry.tx_size;
        }

        histogram
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::transaction::{ErgoBoxCandidate, Input};

    /// Helper to build a minimal transaction with the given tx_id bytes and
    /// input box_id bytes.
    fn make_tx(tx_id_byte: u8, input_box_bytes: &[u8]) -> ErgoTransaction {
        let inputs = input_box_bytes
            .iter()
            .map(|&b| Input {
                box_id: BoxId([b; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            })
            .collect();

        ErgoTransaction {
            inputs,
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                creation_height: 100_000,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([tx_id_byte; 32]),
        }
    }

    #[test]
    fn new_pool_is_empty() {
        let pool = ErgoMemPool::new(100);
        assert_eq!(pool.size(), 0);
        assert!(pool.get_all().is_empty());
    }

    #[test]
    fn put_and_get_roundtrip() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        let tx_id = tx.tx_id;
        pool.put(tx.clone()).unwrap();

        let fetched = pool.get(&tx_id).expect("transaction should be present");
        assert_eq!(*fetched, tx);
        assert_eq!(pool.size(), 1);
    }

    #[test]
    fn put_duplicate_returns_already_exists() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        pool.put(tx.clone()).unwrap();

        let err = pool.put(tx).unwrap_err();
        assert!(
            matches!(err, MempoolError::AlreadyExists(id) if id == TxId([0x01; 32])),
            "expected AlreadyExists, got: {err}",
        );
    }

    #[test]
    fn double_spend_detected() {
        let mut pool = ErgoMemPool::new(100);
        // tx1 spends box 0xAA
        let tx1 = make_tx(0x01, &[0xAA]);
        pool.put(tx1).unwrap();

        // tx2 also tries to spend box 0xAA → double spend
        let tx2 = make_tx(0x02, &[0xAA]);
        let err = pool.put(tx2).unwrap_err();
        assert!(
            matches!(err, MempoolError::DoubleSpend(box_id, spender)
                if box_id == BoxId([0xAA; 32]) && spender == TxId([0x01; 32])),
            "expected DoubleSpend, got: {err}",
        );
    }

    #[test]
    fn remove_returns_transaction() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        let tx_id = tx.tx_id;
        pool.put(tx.clone()).unwrap();

        let removed = pool.remove(&tx_id).expect("should return removed tx");
        assert_eq!(removed, tx);
        assert_eq!(pool.size(), 0);

        // Input index should also be cleaned up.
        assert!(!pool.is_double_spend(&BoxId([0xAA; 32])));
    }

    #[test]
    fn remove_with_double_spends_removes_conflicting_txs() {
        let mut pool = ErgoMemPool::new(100);

        // tx1 spends box 0xAA
        let tx1 = make_tx(0x01, &[0xAA]);
        pool.put(tx1).unwrap();

        // tx2 spends box 0xBB (no conflict)
        let tx2 = make_tx(0x02, &[0xBB]);
        pool.put(tx2).unwrap();

        assert_eq!(pool.size(), 2);

        // Incoming tx also wants to spend box 0xAA → should remove tx1
        let incoming = make_tx(0x03, &[0xAA]);
        pool.remove_with_double_spends(&incoming);

        assert_eq!(pool.size(), 1);
        assert!(pool.get(&TxId([0x01; 32])).is_none(), "tx1 should be gone");
        assert!(
            pool.get(&TxId([0x02; 32])).is_some(),
            "tx2 should remain"
        );
        assert!(!pool.is_double_spend(&BoxId([0xAA; 32])));
    }

    #[test]
    fn pool_full_returns_error() {
        let mut pool = ErgoMemPool::new(2);
        pool.put(make_tx(0x01, &[0xAA])).unwrap();
        pool.put(make_tx(0x02, &[0xBB])).unwrap();

        let err = pool.put(make_tx(0x03, &[0xCC])).unwrap_err();
        assert!(
            matches!(err, MempoolError::PoolFull(2)),
            "expected PoolFull(2), got: {err}",
        );
    }

    #[test]
    fn remove_for_block_removes_conflicting_txs() {
        let mut pool = ErgoMemPool::new(100);

        // tx1 spends box 0xAA
        let tx1 = make_tx(0x01, &[0xAA]);
        pool.put(tx1).unwrap();

        // tx2 spends box 0xBB (no conflict)
        let tx2 = make_tx(0x02, &[0xBB]);
        pool.put(tx2).unwrap();

        assert_eq!(pool.size(), 2);

        // Block contains a tx that spends box 0xAA → should remove tx1
        let block_tx = make_tx(0x03, &[0xAA]);
        pool.remove_for_block(&[block_tx]);

        assert_eq!(pool.size(), 1);
        assert!(pool.get(&TxId([0x01; 32])).is_none(), "tx1 should be removed (conflicting input)");
        assert!(pool.get(&TxId([0x02; 32])).is_some(), "tx2 should remain (no conflict)");
    }

    #[test]
    fn remove_for_block_removes_exact_match() {
        let mut pool = ErgoMemPool::new(100);

        // Put a tx in the pool
        let tx = make_tx(0x01, &[0xAA]);
        let tx_id = tx.tx_id;
        pool.put(tx.clone()).unwrap();
        assert_eq!(pool.size(), 1);

        // Block contains the exact same transaction
        pool.remove_for_block(&[tx]);

        assert_eq!(pool.size(), 0);
        assert!(pool.get(&tx_id).is_none(), "exact tx should be removed");
        assert!(!pool.is_double_spend(&BoxId([0xAA; 32])), "input index should be cleaned up");
    }

    #[test]
    fn get_all_returns_all_transactions() {
        let mut pool = ErgoMemPool::new(100);
        pool.put(make_tx(0x01, &[0xAA])).unwrap();
        pool.put(make_tx(0x02, &[0xBB])).unwrap();
        pool.put(make_tx(0x03, &[0xCC])).unwrap();

        let all = pool.get_all();
        assert_eq!(all.len(), 3);

        // Verify all three tx IDs are present.
        let ids: Vec<TxId> = all.iter().map(|tx| tx.tx_id).collect();
        assert!(ids.contains(&TxId([0x01; 32])));
        assert!(ids.contains(&TxId([0x02; 32])));
        assert!(ids.contains(&TxId([0x03; 32])));
    }

    #[test]
    fn contains_returns_true_for_pooled_tx() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        let tx_id = tx.tx_id;
        pool.put(tx).unwrap();
        assert!(pool.contains(&tx_id));
    }

    #[test]
    fn contains_returns_false_for_unknown_tx() {
        let pool = ErgoMemPool::new(100);
        assert!(!pool.contains(&TxId([0xFF; 32])));
    }

    #[test]
    fn evict_stale_removes_old_transactions() {
        let mut pool = ErgoMemPool::new(100);
        pool.put(make_tx(0x01, &[0xAA])).unwrap();
        pool.put(make_tx(0x02, &[0xBB])).unwrap();

        // With Duration::ZERO every tx is already older → evict all.
        let evicted = pool.evict_stale(Duration::ZERO);
        assert_eq!(evicted.len(), 2);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn evict_stale_keeps_fresh_transactions() {
        let mut pool = ErgoMemPool::new(100);
        pool.put(make_tx(0x01, &[0xAA])).unwrap();

        // With Duration::MAX nothing should be evicted.
        let evicted = pool.evict_stale(Duration::MAX);
        assert!(evicted.is_empty());
        assert_eq!(pool.size(), 1);
    }

    #[test]
    fn get_all_tx_ids_returns_all_ids() {
        let mut pool = ErgoMemPool::new(100);
        pool.put(make_tx(0x01, &[0xAA])).unwrap();
        pool.put(make_tx(0x02, &[0xBB])).unwrap();

        let ids = pool.get_all_tx_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&TxId([0x01; 32])));
        assert!(ids.contains(&TxId([0x02; 32])));
    }

    #[test]
    fn find_output_by_box_id() {
        use ergo_types::transaction::compute_box_id;

        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        let tx_id = tx.tx_id;
        pool.put(tx).unwrap();

        let expected_box_id = compute_box_id(&tx_id, 0);
        let output_ref = pool
            .find_output_by_box_id(&expected_box_id)
            .expect("should find the output");
        assert_eq!(output_ref.tx_id, tx_id);
        assert_eq!(output_ref.index, 0);
        assert_eq!(output_ref.candidate.value, 1_000_000_000);
    }

    #[test]
    fn find_output_by_box_id_not_found() {
        let pool = ErgoMemPool::new(100);
        let bogus = BoxId([0xFF; 32]);
        assert!(pool.find_output_by_box_id(&bogus).is_none());
    }

    #[test]
    fn find_outputs_by_token_id_returns_matching() {
        let mut pool = ErgoMemPool::new(100);
        let token_id = BoxId([0xDE; 32]);
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 500_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                creation_height: 100_000,
                tokens: vec![(token_id, 100)],
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0x01; 32]),
        };
        pool.put(tx).unwrap();

        let results = pool.find_outputs_by_token_id(&token_id);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tx_id, TxId([0x01; 32]));
        assert_eq!(results[0].index, 0);
        assert_eq!(results[0].candidate.tokens[0].1, 100);
    }

    #[test]
    fn find_outputs_by_token_id_empty_when_no_match() {
        let pool = ErgoMemPool::new(100);
        let token_id = BoxId([0xDE; 32]);
        let results = pool.find_outputs_by_token_id(&token_id);
        assert!(results.is_empty());
    }

    #[test]
    fn find_spending_input_returns_spending_tx() {
        let mut pool = ErgoMemPool::new(100);
        let box_id = BoxId([0xAA; 32]);
        let tx = make_tx(0x01, &[0xAA]);
        let tx_id = tx.tx_id;
        pool.put(tx).unwrap();

        let result = pool.find_spending_input(&box_id);
        assert!(result.is_some());
        let (found_tx_id, found_input) = result.unwrap();
        assert_eq!(found_tx_id, tx_id);
        assert_eq!(found_input.box_id, box_id);
    }

    #[test]
    fn find_spending_input_returns_none_when_not_spent() {
        let pool = ErgoMemPool::new(100);
        assert!(pool.find_spending_input(&BoxId([0xFF; 32])).is_none());
    }

    #[test]
    fn put_with_size_stores_size() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        pool.put_with_size(tx, 250).unwrap();
        assert_eq!(pool.size(), 1);
        let histogram = pool.pool_histogram(1, 60_000);
        assert_eq!(histogram.len(), 1);
        assert_eq!(histogram[0].n_txns, 1);
        assert_eq!(histogram[0].total_size, 250);
    }

    #[test]
    fn pool_histogram_empty() {
        let pool = ErgoMemPool::new(100);
        let histogram = pool.pool_histogram(10, 60_000);
        assert_eq!(histogram.len(), 10);
        for bin in &histogram {
            assert_eq!(bin.n_txns, 0);
            assert_eq!(bin.total_size, 0);
        }
    }

    #[test]
    fn pool_histogram_single_tx() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        pool.put_with_size(tx, 100).unwrap();
        let histogram = pool.pool_histogram(5, 60_000);
        assert_eq!(histogram.len(), 5);
        // The tx was just inserted, so wait time is approximately 0 -> bin 0
        assert_eq!(histogram[0].n_txns, 1);
        assert_eq!(histogram[0].total_size, 100);
    }

    #[test]
    fn is_spent_in_mempool_true() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        pool.put(tx).unwrap();

        assert!(pool.is_spent_in_mempool(&BoxId([0xAA; 32])));
    }

    #[test]
    fn is_spent_in_mempool_false() {
        let pool = ErgoMemPool::new(100);
        assert!(!pool.is_spent_in_mempool(&BoxId([0xFF; 32])));
    }

    #[test]
    fn find_outputs_by_tree_hash_matches() {
        let mut pool = ErgoMemPool::new(100);
        let ergo_tree = vec![0x00, 0x08, 0xcd];
        let tree_hash = blake2b256(&ergo_tree);

        let tx = make_tx(0x01, &[0xAA]);
        // make_tx creates an output with ergo_tree_bytes = [0x00, 0x08, 0xcd]
        pool.put(tx).unwrap();

        let results = pool.find_outputs_by_tree_hash(&tree_hash);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tx_id, TxId([0x01; 32]));
        assert_eq!(results[0].index, 0);
        assert_eq!(results[0].candidate.ergo_tree_bytes, ergo_tree);
    }

    #[test]
    fn find_outputs_by_tree_hash_no_match() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        pool.put(tx).unwrap();

        let random_hash = [0xFF; 32];
        let results = pool.find_outputs_by_tree_hash(&random_hash);
        assert!(results.is_empty());
    }

    #[test]
    fn find_txs_by_tree_hash_works() {
        let mut pool = ErgoMemPool::new(100);
        let ergo_tree = vec![0x00, 0x08, 0xcd];
        let tree_hash = blake2b256(&ergo_tree);

        // make_tx creates an output with ergo_tree_bytes = [0x00, 0x08, 0xcd]
        let tx = make_tx(0x01, &[0xAA]);
        pool.put(tx).unwrap();

        let results = pool.find_txs_by_tree_hash(&tree_hash);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tx_id, TxId([0x01; 32]));
    }

    #[test]
    fn find_txs_by_tree_hash_no_match() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        pool.put(tx).unwrap();

        let random_hash = [0xFF; 32];
        let results = pool.find_txs_by_tree_hash(&random_hash);
        assert!(results.is_empty());
    }

    #[test]
    fn find_outputs_by_registers_works() {
        let mut pool = ErgoMemPool::new(100);
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                creation_height: 100_000,
                tokens: Vec::new(),
                additional_registers: vec![
                    (4, vec![0x05, 0x02]), // R4
                    (5, vec![0x0e, 0x04, 0x74, 0x65, 0x73, 0x74]), // R5
                ],
            }],
            tx_id: TxId([0x01; 32]),
        };
        pool.put(tx).unwrap();

        // Search for R4 matching
        let filter = vec![(4u8, vec![0x05, 0x02])];
        let results = pool.find_outputs_by_registers(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tx_id, TxId([0x01; 32]));
        assert_eq!(results[0].index, 0);

        // Search for R4 and R5 both matching
        let filter = vec![
            (4u8, vec![0x05, 0x02]),
            (5u8, vec![0x0e, 0x04, 0x74, 0x65, 0x73, 0x74]),
        ];
        let results = pool.find_outputs_by_registers(&filter);
        assert_eq!(results.len(), 1);

        // Search with R4 matching but R5 not matching
        let filter = vec![
            (4u8, vec![0x05, 0x02]),
            (5u8, vec![0xFF]),
        ];
        let results = pool.find_outputs_by_registers(&filter);
        assert!(results.is_empty());
    }

    #[test]
    fn find_outputs_by_registers_no_match() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]); // no registers
        pool.put(tx).unwrap();

        let filter = vec![(4u8, vec![0x05, 0x02])];
        let results = pool.find_outputs_by_registers(&filter);
        assert!(results.is_empty());
    }

    #[test]
    fn find_outputs_by_registers_empty_filter() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        pool.put(tx).unwrap();

        let filter: Vec<(u8, Vec<u8>)> = Vec::new();
        let results = pool.find_outputs_by_registers(&filter);
        assert!(results.is_empty());
    }

    #[test]
    fn validate_for_pool_rejects_oversized() {
        let tx_id = TxId([0xaa; 32]);
        let result = validate_for_pool(100_000, &[], 98_304, &tx_id);
        assert!(matches!(
            result,
            Err(MempoolError::TxTooLarge {
                size: 100_000,
                max: 98_304
            })
        ));
    }

    #[test]
    fn validate_for_pool_accepts_within_limit() {
        let tx_id = TxId([0xaa; 32]);
        assert!(validate_for_pool(50_000, &[], 98_304, &tx_id).is_ok());
    }

    #[test]
    fn validate_for_pool_rejects_blacklisted() {
        let tx_id = TxId([0xaa; 32]);
        let blacklist = vec!["aa".repeat(32)];
        let result = validate_for_pool(50_000, &blacklist, 98_304, &tx_id);
        assert!(matches!(result, Err(MempoolError::Blacklisted { .. })));
    }

    #[test]
    fn validate_for_pool_passes_non_blacklisted() {
        let tx_id = TxId([0xaa; 32]);
        let blacklist = vec!["bb".repeat(32)];
        assert!(validate_for_pool(50_000, &blacklist, 98_304, &tx_id).is_ok());
    }

    #[test]
    fn test_take_all_cloned_returns_copies() {
        let mut pool = ErgoMemPool::new(100);
        pool.put(make_tx(0x01, &[0xAA])).unwrap();
        pool.put(make_tx(0x02, &[0xBB])).unwrap();
        pool.put(make_tx(0x03, &[0xCC])).unwrap();

        let cloned = pool.take_all_cloned();
        assert_eq!(cloned.len(), 3);

        // Verify all three tx IDs are present.
        let ids: Vec<TxId> = cloned.iter().map(|tx| tx.tx_id).collect();
        assert!(ids.contains(&TxId([0x01; 32])));
        assert!(ids.contains(&TxId([0x02; 32])));
        assert!(ids.contains(&TxId([0x03; 32])));

        // Verify they are independent copies: pool still has 3 txs.
        assert_eq!(pool.size(), 3);

        // Dropping the cloned vec doesn't affect the pool.
        drop(cloned);
        assert_eq!(pool.size(), 3);
        assert!(pool.get(&TxId([0x01; 32])).is_some());
    }

    #[test]
    fn test_take_all_cloned_empty_pool() {
        let pool = ErgoMemPool::new(100);
        let cloned = pool.take_all_cloned();
        assert!(cloned.is_empty());
    }

    #[test]
    fn audit_flags_txs_with_missing_inputs() {
        let mut pool = ErgoMemPool::new(100);
        pool.put(make_tx(0x01, &[0xAA])).unwrap();
        pool.put(make_tx(0x02, &[0xBB])).unwrap();
        // Only box 0xAA exists
        let invalid = pool.audit_against_utxo(
            |box_id| box_id.0 == [0xAA; 32],
            7_000_000,
        );
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0], TxId([0x02; 32]));
    }

    #[test]
    fn audit_keeps_txs_with_existing_inputs() {
        let mut pool = ErgoMemPool::new(100);
        pool.put(make_tx(0x01, &[0xAA])).unwrap();
        // All inputs exist
        let invalid = pool.audit_against_utxo(|_| true, 7_000_000);
        assert!(invalid.is_empty());
    }

    #[test]
    fn audit_respects_cost_limit() {
        let mut pool = ErgoMemPool::new(100);
        for i in 1..=20u8 {
            pool.put(make_tx(i, &[i])).unwrap();
        }
        // Very low cost limit: 10000 + 1*2000 = 12000 per tx, limit 25000 -> ~2 txs checked
        let invalid = pool.audit_against_utxo(|_| false, 25_000);
        assert!(invalid.len() <= 3); // only a few checked before limit
    }

    #[test]
    fn remove_batch_removes_multiple() {
        let mut pool = ErgoMemPool::new(100);
        pool.put(make_tx(0x01, &[0xAA])).unwrap();
        pool.put(make_tx(0x02, &[0xBB])).unwrap();
        pool.put(make_tx(0x03, &[0xCC])).unwrap();
        pool.remove_batch(&[TxId([0x01; 32]), TxId([0x03; 32])]);
        assert_eq!(pool.size(), 1);
        assert!(pool.get(&TxId([0x02; 32])).is_some());
    }

    #[test]
    fn miners_fee_ergo_tree_matches_hex() {
        let expected = hex::decode(
            "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
        ).unwrap();
        assert_eq!(MINERS_FEE_ERGO_TREE, expected.as_slice());
    }

    #[test]
    fn extract_fee_identifies_fee_output() {
        let fee_tree = hex::decode(
            "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
        ).unwrap();
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: 999_000_000,
                    ergo_tree_bytes: vec![0x00],
                    creation_height: 100,
                    tokens: vec![],
                    additional_registers: vec![],
                },
                ErgoBoxCandidate {
                    value: 1_000_000,
                    ergo_tree_bytes: fee_tree,
                    creation_height: 100,
                    tokens: vec![],
                    additional_registers: vec![],
                },
            ],
            tx_id: TxId([0x01; 32]),
        };
        assert_eq!(extract_fee(&tx), 1_000_000);
    }

    #[test]
    fn extract_fee_returns_zero_when_no_fee_output() {
        let tx = make_tx(0x01, &[0xAA]);
        assert_eq!(extract_fee(&tx), 0);
    }

    #[test]
    fn compute_weight_basic() {
        // fee=1000, size=200 -> weight = 1000*1024/200 = 5120
        assert_eq!(compute_weight(1000, 200), 5120);
        // fee=100000, size=200 -> weight = 100000*1024/200 = 512000
        assert_eq!(compute_weight(100000, 200), 512000);
    }

    #[test]
    fn compute_weight_zero_size() {
        assert_eq!(compute_weight(1000, 0), 0);
    }

    #[test]
    fn compute_weight_zero_fee() {
        assert_eq!(compute_weight(0, 200), 0);
    }

    #[test]
    fn get_all_returns_priority_order() {
        let fee_tree = hex::decode(
            "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
        ).unwrap();
        let mut pool = ErgoMemPool::new(100);

        // Low fee tx (1000 nanoERG, 200 bytes) -> weight = 1000*1024/200 = 5120
        let tx_low = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x01; 32]),
        };
        pool.put_with_size(tx_low, 200).unwrap();

        // High fee tx (100000 nanoERG, 200 bytes) -> weight = 100000*1024/200 = 512000
        let tx_high = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xBB; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 100000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x02; 32]),
        };
        pool.put_with_size(tx_high, 200).unwrap();

        let all = pool.get_all();
        assert_eq!(all.len(), 2);
        // High fee should come first
        assert_eq!(all[0].tx_id, TxId([0x02; 32]));
        assert_eq!(all[1].tx_id, TxId([0x01; 32]));
    }

    #[test]
    fn take_all_cloned_returns_priority_order() {
        let fee_tree = hex::decode(
            "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
        ).unwrap();
        let mut pool = ErgoMemPool::new(100);

        // Low fee first
        let tx_low = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 500,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x01; 32]),
        };
        pool.put_with_size(tx_low, 200).unwrap();

        // High fee second
        let tx_high = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xBB; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 50000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x02; 32]),
        };
        pool.put_with_size(tx_high, 200).unwrap();

        let cloned = pool.take_all_cloned();
        assert_eq!(cloned.len(), 2);
        assert_eq!(cloned[0].tx_id, TxId([0x02; 32]));
        assert_eq!(cloned[1].tx_id, TxId([0x01; 32]));
    }

    #[test]
    fn full_pool_evicts_lowest_priority() {
        let fee_tree = hex::decode(
            "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
        ).unwrap();
        let mut pool = ErgoMemPool::new(2);

        // Add 2 low-fee txs
        let tx1 = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x01; 32]),
        };
        pool.put_with_size(tx1, 200).unwrap();

        let tx2 = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xBB; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 2000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x02; 32]),
        };
        pool.put_with_size(tx2, 200).unwrap();
        assert_eq!(pool.size(), 2);

        // Add high-fee tx -> should evict tx1 (lowest weight)
        let tx3 = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xCC; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 100000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x03; 32]),
        };
        pool.put_with_size(tx3, 200).unwrap();
        assert_eq!(pool.size(), 2);
        assert!(
            pool.get(&TxId([0x01; 32])).is_none(),
            "lowest-fee tx should be evicted"
        );
        assert!(
            pool.get(&TxId([0x03; 32])).is_some(),
            "high-fee tx should be present"
        );
    }

    #[test]
    fn full_pool_rejects_lower_priority_tx() {
        let fee_tree = hex::decode(
            "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
        ).unwrap();
        let mut pool = ErgoMemPool::new(1);

        // Add high-fee tx
        let tx1 = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 100000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x01; 32]),
        };
        pool.put_with_size(tx1, 200).unwrap();

        // Try to add lower-fee tx -> should be rejected
        let tx2 = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xBB; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x02; 32]),
        };
        let err = pool.put_with_size(tx2, 200).unwrap_err();
        assert!(matches!(err, MempoolError::PoolFull(1)));
        assert_eq!(pool.size(), 1);
        assert!(pool.get(&TxId([0x01; 32])).is_some());
    }

    #[test]
    fn get_with_size_returns_tx_and_size() {
        let mut pool = ErgoMemPool::new(100);
        let tx = make_tx(0x01, &[0xAA]);
        let tx_id = tx.tx_id;
        pool.put_with_size(tx, 350).unwrap();

        let (fetched, size) = pool.get_with_size(&tx_id).expect("should be present");
        assert_eq!(fetched.tx_id, tx_id);
        assert_eq!(size, 350);
    }

    #[test]
    fn get_all_with_size_returns_priority_order() {
        let fee_tree = hex::decode(
            "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
        ).unwrap();
        let mut pool = ErgoMemPool::new(100);

        let tx_low = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x01; 32]),
        };
        pool.put_with_size(tx_low, 200).unwrap();

        let tx_high = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xBB; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 100000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x02; 32]),
        };
        pool.put_with_size(tx_high, 300).unwrap();

        let all = pool.get_all_with_size();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0.tx_id, TxId([0x02; 32]));
        assert_eq!(all[0].1, 300);
        assert_eq!(all[1].0.tx_id, TxId([0x01; 32]));
        assert_eq!(all[1].1, 200);
    }

    #[test]
    fn ordered_index_consistent_after_remove() {
        let fee_tree = hex::decode(
            "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304"
        ).unwrap();
        let mut pool = ErgoMemPool::new(100);

        let tx1 = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 5000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x01; 32]),
        };
        pool.put_with_size(tx1, 200).unwrap();

        let tx2 = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xBB; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 10000,
                ergo_tree_bytes: fee_tree.clone(),
                creation_height: 100,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0x02; 32]),
        };
        pool.put_with_size(tx2, 200).unwrap();

        // Remove tx2 (highest priority)
        pool.remove(&TxId([0x02; 32]));

        let all = pool.get_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].tx_id, TxId([0x01; 32]));
    }
}
