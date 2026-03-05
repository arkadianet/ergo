//! Core block-indexing logic for the extra-indexer.
//!
//! [`index_block`] processes one block's transactions at a given height,
//! creating and updating all indexed types (boxes, transactions, addresses,
//! contract templates, tokens).  Updates are accumulated in an
//! [`IndexerBuffer`] that is flushed to the DB when it exceeds a threshold.

use ergo_types::modifier_id::ModifierId;
use ergo_types::transaction::ErgoTransaction;
use ergo_wire::box_ser::compute_box_id;

use crate::db::{
    global_box_index_key, global_tx_index_key, indexed_height_key, numeric_box_key, numeric_tx_key,
    token_key, tree_hash_key, ExtraIndexerDb, IndexerDbError,
};
use crate::segment::{
    find_and_negate_index, find_and_unnegate_index, remove_index_entry, split_segments,
};
use crate::template::template_hash;
use crate::types::{
    BalanceInfo, IndexedContractTemplate, IndexedErgoAddress, IndexedErgoBox,
    IndexedErgoTransaction, IndexedToken, NumericBoxIndex, NumericTxIndex,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of buffered operations before an automatic flush to the DB.
const FLUSH_THRESHOLD: usize = 20_000;

// ---------------------------------------------------------------------------
// IndexerState
// ---------------------------------------------------------------------------

/// Mutable progress state carried across blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexerState {
    /// The last successfully indexed block height.
    pub indexed_height: u32,
    /// The next global transaction index to assign.
    pub global_tx_index: u64,
    /// The next global box index to assign.
    pub global_box_index: u64,
}

// ---------------------------------------------------------------------------
// IndexerBuffer
// ---------------------------------------------------------------------------

/// In-memory write buffer that accumulates indexed entries before flushing
/// to the underlying RocksDB in a single atomic batch.
pub struct IndexerBuffer {
    entries: Vec<([u8; 32], Vec<u8>)>,
    deletes: Vec<[u8; 32]>,
    mod_count: usize,
}

impl IndexerBuffer {
    /// Create a new empty buffer.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            deletes: Vec::new(),
            mod_count: 0,
        }
    }

    /// Append a key-value entry to the buffer.
    pub fn push(&mut self, key: [u8; 32], value: Vec<u8>) {
        self.entries.push((key, value));
        self.mod_count += 1;
    }

    /// Append a key to be deleted when the buffer is flushed.
    pub fn push_delete(&mut self, key: [u8; 32]) {
        self.deletes.push(key);
        self.mod_count += 1;
    }

    /// Look up the most recent entry for `key` in the buffer.
    pub fn find(&self, key: &[u8; 32]) -> Option<&[u8]> {
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// Current number of buffered modifications.
    pub fn mod_count(&self) -> usize {
        self.mod_count
    }
}

impl Default for IndexerBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// flush_buffer
// ---------------------------------------------------------------------------

/// Atomically flush the buffer contents to the database and update progress
/// counters.
pub fn flush_buffer(
    db: &ExtraIndexerDb,
    state: &IndexerState,
    buffer: &mut IndexerBuffer,
) -> Result<(), IndexerDbError> {
    let mut batch = db.new_batch();
    let cf = db.cf();
    for (key, value) in buffer.entries.drain(..) {
        batch.put_cf(&cf, key, &value);
    }
    for key in buffer.deletes.drain(..) {
        batch.delete_cf(&cf, key);
    }
    db.write_batch(batch)?;

    // Persist progress counters.
    db.set_progress_u32(&indexed_height_key(), state.indexed_height)?;
    db.set_progress_u64(&global_tx_index_key(), state.global_tx_index)?;
    db.set_progress_u64(&global_box_index_key(), state.global_box_index)?;

    buffer.mod_count = 0;
    Ok(())
}

// ---------------------------------------------------------------------------
// load_entry helper
// ---------------------------------------------------------------------------

/// Load a deserializable entry from the buffer first, falling back to the DB.
fn load_entry<T, F>(
    db: &ExtraIndexerDb,
    buffer: &IndexerBuffer,
    key: &[u8; 32],
    deserialize: F,
) -> Result<Option<T>, IndexerDbError>
where
    F: Fn(&[u8]) -> Result<T, IndexerDbError>,
{
    if let Some(data) = buffer.find(key) {
        return Ok(Some(deserialize(data)?));
    }
    match db.get(key)? {
        Some(data) => Ok(Some(deserialize(&data)?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// index_block
// ---------------------------------------------------------------------------

/// Index a single block's transactions at the given height.
///
/// `tx_data` is a slice of `(raw_tx_bytes, parsed_transaction)` pairs.
/// Updates are accumulated in `buffer` and flushed automatically when the
/// modification count exceeds [`FLUSH_THRESHOLD`].
pub fn index_block(
    db: &ExtraIndexerDb,
    state: &mut IndexerState,
    buffer: &mut IndexerBuffer,
    tx_data: &[(Vec<u8>, ErgoTransaction)],
    height: u32,
) -> Result<(), IndexerDbError> {
    let is_genesis = height == 1;

    for (tx_index, (tx_bytes, tx)) in tx_data.iter().enumerate() {
        // First input box ID used for new-token detection.
        let first_input_box_id: Option<[u8; 32]> = tx.inputs.first().map(|i| i.box_id.0);

        let mut input_global_indexes: Vec<u64> = Vec::new();
        let mut output_global_indexes: Vec<u64> = Vec::new();

        // -----------------------------------------------------------------
        // Process inputs (skip for genesis block)
        // -----------------------------------------------------------------
        if !is_genesis {
            for input in &tx.inputs {
                let box_key = input.box_id.0;

                // Load the IndexedErgoBox.
                let maybe_box = load_entry(db, buffer, &box_key, IndexedErgoBox::deserialize)?;

                if let Some(mut indexed_box) = maybe_box {
                    // Mark the box as spent.
                    indexed_box.spending_tx_id = Some(ModifierId(tx.tx_id.0));
                    indexed_box.spending_height = Some(height);
                    buffer.push(box_key, indexed_box.serialize());
                    input_global_indexes.push(indexed_box.global_index);

                    // --- Update address ---
                    let addr_key = tree_hash_key(&indexed_box.ergo_tree);
                    let maybe_addr =
                        load_entry(db, buffer, &addr_key, IndexedErgoAddress::deserialize)?;

                    if let Some(mut addr) = maybe_addr {
                        // Negate box index in address.
                        let (_, seg_updates) = find_and_negate_index(
                            &mut addr.box_indexes,
                            indexed_box.global_index,
                            db,
                            &addr_key,
                            addr.box_segment_count,
                            true,
                        )?;
                        for (seg_key, seg_data) in seg_updates {
                            buffer.push(seg_key, seg_data);
                        }

                        // Subtract balance.
                        addr.balance.nano_ergs =
                            addr.balance.nano_ergs.saturating_sub(indexed_box.value);

                        // Subtract token balances.
                        for (token_id, amount) in &indexed_box.tokens {
                            if let Some(pos) = addr
                                .balance
                                .tokens
                                .iter()
                                .position(|(id, _)| id == token_id)
                            {
                                let current = addr.balance.tokens[pos].1;
                                if current <= *amount {
                                    addr.balance.tokens.remove(pos);
                                } else {
                                    addr.balance.tokens[pos].1 -= amount;
                                }
                            }
                        }

                        buffer.push(addr_key, addr.serialize());
                    }

                    // --- Update contract template ---
                    let tmpl_hash = template_hash(&indexed_box.ergo_tree);
                    let tmpl_key = crate::db::template_hash_key(&tmpl_hash);
                    let maybe_tmpl =
                        load_entry(db, buffer, &tmpl_key, IndexedContractTemplate::deserialize)?;

                    if let Some(mut tmpl) = maybe_tmpl {
                        let (_, seg_updates) = find_and_negate_index(
                            &mut tmpl.box_indexes,
                            indexed_box.global_index,
                            db,
                            &tmpl_key,
                            tmpl.box_segment_count,
                            true,
                        )?;
                        for (seg_key, seg_data) in seg_updates {
                            buffer.push(seg_key, seg_data);
                        }
                        buffer.push(tmpl_key, tmpl.serialize());
                    }

                    // --- Update tokens ---
                    for (token_id, _) in &indexed_box.tokens {
                        let tk_key = token_key(token_id);
                        let maybe_token =
                            load_entry(db, buffer, &tk_key, IndexedToken::deserialize)?;

                        if let Some(mut token) = maybe_token {
                            let (_, seg_updates) = find_and_negate_index(
                                &mut token.box_indexes,
                                indexed_box.global_index,
                                db,
                                &tk_key,
                                token.box_segment_count,
                                true,
                            )?;
                            for (seg_key, seg_data) in seg_updates {
                                buffer.push(seg_key, seg_data);
                            }
                            buffer.push(tk_key, token.serialize());
                        }
                    }
                }
            }
        }

        // -----------------------------------------------------------------
        // Process outputs
        // -----------------------------------------------------------------
        for (output_idx, output) in tx.output_candidates.iter().enumerate() {
            let box_id = compute_box_id(output, &tx.tx_id, output_idx as u16);

            // Create IndexedErgoBox.
            let indexed_box = IndexedErgoBox {
                inclusion_height: height,
                spending_tx_id: None,
                spending_height: None,
                box_id: ModifierId(box_id.0),
                ergo_tree: output.ergo_tree_bytes.clone(),
                value: output.value,
                tokens: output
                    .tokens
                    .iter()
                    .map(|(id, amt)| (ModifierId(id.0), *amt))
                    .collect(),
                global_index: state.global_box_index,
            };
            buffer.push(box_id.0, indexed_box.serialize());

            // Create NumericBoxIndex.
            let num_box = NumericBoxIndex {
                n: state.global_box_index,
                box_id: ModifierId(box_id.0),
            };
            buffer.push(numeric_box_key(state.global_box_index), num_box.serialize());

            output_global_indexes.push(state.global_box_index);

            // --- Update/create address ---
            let addr_key = tree_hash_key(&output.ergo_tree_bytes);
            let mut addr = load_entry(db, buffer, &addr_key, IndexedErgoAddress::deserialize)?
                .unwrap_or_else(|| IndexedErgoAddress {
                    tree_hash: addr_key,
                    balance: BalanceInfo {
                        nano_ergs: 0,
                        tokens: Vec::new(),
                    },
                    tx_indexes: Vec::new(),
                    box_indexes: Vec::new(),
                    box_segment_count: 0,
                    tx_segment_count: 0,
                });

            addr.box_indexes.push(state.global_box_index as i64);
            addr.balance.nano_ergs += output.value;

            // Add token balances.
            for (token_id, amount) in &output.tokens {
                let mid = ModifierId(token_id.0);
                if let Some(pos) = addr.balance.tokens.iter().position(|(id, _)| *id == mid) {
                    addr.balance.tokens[pos].1 += amount;
                } else {
                    addr.balance.tokens.push((mid, *amount));
                }
            }

            // Check segment overflow.
            let seg_updates = split_segments(
                &mut addr.box_indexes,
                &mut addr.box_segment_count,
                &addr_key,
                true,
            );
            for (seg_key, seg_data) in seg_updates {
                buffer.push(seg_key, seg_data);
            }

            buffer.push(addr_key, addr.serialize());

            // --- Update/create contract template ---
            let tmpl_hash = template_hash(&output.ergo_tree_bytes);
            let tmpl_key = crate::db::template_hash_key(&tmpl_hash);
            let mut tmpl = load_entry(db, buffer, &tmpl_key, IndexedContractTemplate::deserialize)?
                .unwrap_or_else(|| IndexedContractTemplate {
                    template_hash: tmpl_key,
                    box_indexes: Vec::new(),
                    box_segment_count: 0,
                });

            tmpl.box_indexes.push(state.global_box_index as i64);
            let seg_updates = split_segments(
                &mut tmpl.box_indexes,
                &mut tmpl.box_segment_count,
                &tmpl_key,
                true,
            );
            for (seg_key, seg_data) in seg_updates {
                buffer.push(seg_key, seg_data);
            }
            buffer.push(tmpl_key, tmpl.serialize());

            // --- Update/create token entries ---
            for (token_id, amount) in &output.tokens {
                let tk_key = token_key(&ModifierId(token_id.0));
                let mut token = load_entry(db, buffer, &tk_key, IndexedToken::deserialize)?
                    .unwrap_or_else(|| {
                        // New token detection: if token_id matches the first
                        // input box ID, this is a newly minted token.
                        let is_new = first_input_box_id
                            .map(|fib| fib == token_id.0)
                            .unwrap_or(false);

                        IndexedToken {
                            token_id: ModifierId(token_id.0),
                            box_id: if is_new {
                                Some(ModifierId(box_id.0))
                            } else {
                                None
                            },
                            amount: if is_new { Some(*amount) } else { None },
                            name: None,
                            description: None,
                            decimals: None,
                            box_indexes: Vec::new(),
                            box_segment_count: 0,
                        }
                    });

                token.box_indexes.push(state.global_box_index as i64);
                let seg_updates = split_segments(
                    &mut token.box_indexes,
                    &mut token.box_segment_count,
                    &tk_key,
                    true,
                );
                for (seg_key, seg_data) in seg_updates {
                    buffer.push(seg_key, seg_data);
                }
                buffer.push(tk_key, token.serialize());
            }

            state.global_box_index += 1;
        }

        // -----------------------------------------------------------------
        // Create IndexedErgoTransaction
        // -----------------------------------------------------------------
        let indexed_tx = IndexedErgoTransaction {
            tx_id: ModifierId(tx.tx_id.0),
            index: tx_index as u32,
            height,
            size: tx_bytes.len() as u32,
            global_index: state.global_tx_index,
            input_indexes: input_global_indexes,
            output_indexes: output_global_indexes,
        };
        buffer.push(tx.tx_id.0, indexed_tx.serialize());

        // Create NumericTxIndex.
        let num_tx = NumericTxIndex {
            n: state.global_tx_index,
            tx_id: ModifierId(tx.tx_id.0),
        };
        buffer.push(numeric_tx_key(state.global_tx_index), num_tx.serialize());

        state.global_tx_index += 1;
    }

    // Update indexed height.
    state.indexed_height = height;

    // Auto-flush if threshold exceeded.
    if buffer.mod_count >= FLUSH_THRESHOLD {
        flush_buffer(db, state, buffer)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// remove_after  (rollback)
// ---------------------------------------------------------------------------

/// Undo all indexing above `target_height`.
///
/// Walks backward through numeric indexes to find which transactions and
/// boxes belong to heights above the target, then removes or reverts them.
/// Direct DB reads/writes are used (no buffering) since rollbacks are rare.
pub fn remove_after(
    db: &ExtraIndexerDb,
    state: &mut IndexerState,
    buffer: &mut IndexerBuffer,
    target_height: u32,
) -> Result<(), IndexerDbError> {
    // 1. Flush any buffered changes first.
    flush_buffer(db, state, buffer)?;

    // 2. Find tx_target: the first global tx index whose height > target_height.
    let mut tx_target = 0u64;
    if state.global_tx_index > 0 {
        tx_target = state.global_tx_index; // default: nothing to undo
        for n in (0..state.global_tx_index).rev() {
            let ntx_key = numeric_tx_key(n);
            let ntx_data = db
                .get(&ntx_key)?
                .ok_or_else(|| IndexerDbError::Codec(format!("missing NumericTxIndex at {n}")))?;
            let ntx = NumericTxIndex::deserialize(&ntx_data)?;
            let tx_data = db.get(&ntx.tx_id.0)?.ok_or_else(|| {
                IndexerDbError::Codec(format!(
                    "missing IndexedErgoTransaction for tx {}",
                    hex::encode(ntx.tx_id.0)
                ))
            })?;
            let itx = IndexedErgoTransaction::deserialize(&tx_data)?;
            if itx.height <= target_height {
                tx_target = n + 1;
                break;
            }
            if n == 0 {
                tx_target = 0;
            }
        }
    }

    // 3. Find box_target similarly.
    let mut box_target = 0u64;
    if state.global_box_index > 0 {
        box_target = state.global_box_index; // default: nothing to undo
        for n in (0..state.global_box_index).rev() {
            let nb_key = numeric_box_key(n);
            let nb_data = db
                .get(&nb_key)?
                .ok_or_else(|| IndexerDbError::Codec(format!("missing NumericBoxIndex at {n}")))?;
            let nb = NumericBoxIndex::deserialize(&nb_data)?;
            let box_data = db.get(&nb.box_id.0)?.ok_or_else(|| {
                IndexerDbError::Codec(format!(
                    "missing IndexedErgoBox for box {}",
                    hex::encode(nb.box_id.0)
                ))
            })?;
            let ibox = IndexedErgoBox::deserialize(&box_data)?;
            if ibox.inclusion_height <= target_height {
                box_target = n + 1;
                break;
            }
            if n == 0 {
                box_target = 0;
            }
        }
    }

    // 4. Undo transactions (walk backward from state.global_tx_index - 1 to tx_target).
    if state.global_tx_index > tx_target {
        for n in (tx_target..state.global_tx_index).rev() {
            let ntx_key = numeric_tx_key(n);
            let ntx_data = db.get(&ntx_key)?.ok_or_else(|| {
                IndexerDbError::Codec(format!("missing NumericTxIndex at {n} during undo"))
            })?;
            let ntx = NumericTxIndex::deserialize(&ntx_data)?;
            let tx_data = db.get(&ntx.tx_id.0)?.ok_or_else(|| {
                IndexerDbError::Codec(format!(
                    "missing IndexedErgoTransaction during undo for tx {}",
                    hex::encode(ntx.tx_id.0)
                ))
            })?;
            let itx = IndexedErgoTransaction::deserialize(&tx_data)?;

            // For each input_index, restore the spent box.
            for &input_idx in &itx.input_indexes {
                let inb_key = numeric_box_key(input_idx);
                let inb_data = match db.get(&inb_key)? {
                    Some(d) => d,
                    None => continue,
                };
                let inb = NumericBoxIndex::deserialize(&inb_data)?;
                let ibox_data = match db.get(&inb.box_id.0)? {
                    Some(d) => d,
                    None => continue,
                };
                let mut ibox = IndexedErgoBox::deserialize(&ibox_data)?;

                // Clear spending fields.
                ibox.spending_tx_id = None;
                ibox.spending_height = None;
                db.put(&inb.box_id.0, &ibox.serialize())?;

                // Un-negate address box index and restore balance.
                let addr_key = tree_hash_key(&ibox.ergo_tree);
                if let Some(addr_data) = db.get(&addr_key)? {
                    let mut addr = IndexedErgoAddress::deserialize(&addr_data)?;

                    let (_, seg_updates) = find_and_unnegate_index(
                        &mut addr.box_indexes,
                        ibox.global_index,
                        db,
                        &addr_key,
                        addr.box_segment_count,
                        true,
                    )?;
                    for (seg_key, seg_data) in &seg_updates {
                        db.put(seg_key, seg_data)?;
                    }

                    // Add back balance.
                    addr.balance.nano_ergs += ibox.value;
                    for (token_id, amount) in &ibox.tokens {
                        if let Some(pos) = addr
                            .balance
                            .tokens
                            .iter()
                            .position(|(id, _)| id == token_id)
                        {
                            addr.balance.tokens[pos].1 += amount;
                        } else {
                            addr.balance.tokens.push((*token_id, *amount));
                        }
                    }

                    db.put(&addr_key, &addr.serialize())?;
                }

                // Un-negate template box index.
                let tmpl_hash = template_hash(&ibox.ergo_tree);
                let tmpl_key = crate::db::template_hash_key(&tmpl_hash);
                if let Some(tmpl_data) = db.get(&tmpl_key)? {
                    let mut tmpl = IndexedContractTemplate::deserialize(&tmpl_data)?;
                    let (_, seg_updates) = find_and_unnegate_index(
                        &mut tmpl.box_indexes,
                        ibox.global_index,
                        db,
                        &tmpl_key,
                        tmpl.box_segment_count,
                        true,
                    )?;
                    for (seg_key, seg_data) in &seg_updates {
                        db.put(seg_key, seg_data)?;
                    }
                    db.put(&tmpl_key, &tmpl.serialize())?;
                }

                // Un-negate token box indexes.
                for (token_id, _) in &ibox.tokens {
                    let tk_key = token_key(token_id);
                    if let Some(tk_data) = db.get(&tk_key)? {
                        let mut token = IndexedToken::deserialize(&tk_data)?;
                        let (_, seg_updates) = find_and_unnegate_index(
                            &mut token.box_indexes,
                            ibox.global_index,
                            db,
                            &tk_key,
                            token.box_segment_count,
                            true,
                        )?;
                        for (seg_key, seg_data) in &seg_updates {
                            db.put(seg_key, seg_data)?;
                        }
                        db.put(&tk_key, &token.serialize())?;
                    }
                }
            }

            // Delete the tx entry and its numeric index.
            db.delete(&ntx.tx_id.0)?;
            db.delete(&ntx_key)?;
        }
    }

    // 5. Undo boxes (walk backward from state.global_box_index - 1 to box_target).
    if state.global_box_index > box_target {
        for n in (box_target..state.global_box_index).rev() {
            let nb_key = numeric_box_key(n);
            let nb_data = db.get(&nb_key)?.ok_or_else(|| {
                IndexerDbError::Codec(format!("missing NumericBoxIndex at {n} during box undo"))
            })?;
            let nb = NumericBoxIndex::deserialize(&nb_data)?;
            let box_data = db.get(&nb.box_id.0)?.ok_or_else(|| {
                IndexerDbError::Codec(format!(
                    "missing IndexedErgoBox during undo for box {}",
                    hex::encode(nb.box_id.0)
                ))
            })?;
            let ibox = IndexedErgoBox::deserialize(&box_data)?;

            // Remove from address: subtract balance, remove box index.
            let addr_key = tree_hash_key(&ibox.ergo_tree);
            if let Some(addr_data) = db.get(&addr_key)? {
                let mut addr = IndexedErgoAddress::deserialize(&addr_data)?;

                let (_, seg_updates) = remove_index_entry(
                    &mut addr.box_indexes,
                    ibox.global_index,
                    db,
                    &addr_key,
                    addr.box_segment_count,
                    true,
                )?;
                for (seg_key, seg_data) in &seg_updates {
                    db.put(seg_key, seg_data)?;
                }

                addr.balance.nano_ergs = addr.balance.nano_ergs.saturating_sub(ibox.value);
                for (token_id, amount) in &ibox.tokens {
                    if let Some(pos) = addr
                        .balance
                        .tokens
                        .iter()
                        .position(|(id, _)| id == token_id)
                    {
                        let current = addr.balance.tokens[pos].1;
                        if current <= *amount {
                            addr.balance.tokens.remove(pos);
                        } else {
                            addr.balance.tokens[pos].1 -= amount;
                        }
                    }
                }

                db.put(&addr_key, &addr.serialize())?;
            }

            // Remove from template.
            let tmpl_hash = template_hash(&ibox.ergo_tree);
            let tmpl_key = crate::db::template_hash_key(&tmpl_hash);
            if let Some(tmpl_data) = db.get(&tmpl_key)? {
                let mut tmpl = IndexedContractTemplate::deserialize(&tmpl_data)?;
                let (_, seg_updates) = remove_index_entry(
                    &mut tmpl.box_indexes,
                    ibox.global_index,
                    db,
                    &tmpl_key,
                    tmpl.box_segment_count,
                    true,
                )?;
                for (seg_key, seg_data) in &seg_updates {
                    db.put(seg_key, seg_data)?;
                }
                db.put(&tmpl_key, &tmpl.serialize())?;
            }

            // Remove from tokens.
            for (token_id, _) in &ibox.tokens {
                let tk_key = token_key(token_id);
                if let Some(tk_data) = db.get(&tk_key)? {
                    let mut token = IndexedToken::deserialize(&tk_data)?;

                    // Remove box index from token.
                    let (_, seg_updates) = remove_index_entry(
                        &mut token.box_indexes,
                        ibox.global_index,
                        db,
                        &tk_key,
                        token.box_segment_count,
                        true,
                    )?;
                    for (seg_key, seg_data) in &seg_updates {
                        db.put(seg_key, seg_data)?;
                    }

                    // If this box created the token, delete the token entry.
                    if token.box_id.as_ref() == Some(&ibox.box_id) {
                        db.delete(&tk_key)?;
                    } else {
                        db.put(&tk_key, &token.serialize())?;
                    }
                }
            }

            // Delete box entry and numeric index.
            db.delete(&nb.box_id.0)?;
            db.delete(&nb_key)?;
        }
    }

    // 6. Update state and persist progress.
    state.global_tx_index = tx_target;
    state.global_box_index = box_target;
    state.indexed_height = target_height;

    db.set_progress_u32(&indexed_height_key(), state.indexed_height)?;
    db.set_progress_u64(&global_tx_index_key(), state.global_tx_index)?;
    db.set_progress_u64(&global_box_index_key(), state.global_box_index)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::transaction::{BoxId, ErgoBoxCandidate, Input, TxId};

    // Valid P2PK ErgoTree bytes for distinct "addresses" used in tests.
    //
    // Format: [0x00, 0x08, 0xCD] + 33-byte compressed secp256k1 pubkey.
    //
    // TREE_A uses the generator point G of secp256k1.
    // TREE_B uses 2*G.
    // TREE_C uses another distinct known point.
    // sigma-rust requires fully valid ErgoTree bytes; invalid bytes cause a panic in compute_box_id.

    /// P2PK tree for generator point G.
    fn tree_a() -> Vec<u8> {
        let mut v = vec![0x00, 0x08, 0xCD];
        v.extend_from_slice(
            &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        );
        v
    }

    /// P2PK tree for 2*G.
    fn tree_b() -> Vec<u8> {
        let mut v = vec![0x00, 0x08, 0xCD];
        v.extend_from_slice(
            &hex::decode("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap(),
        );
        v
    }

    /// Create a simple transaction for testing with the given outputs and no
    /// inputs.
    fn make_test_tx(
        tx_id: [u8; 32],
        outputs: Vec<ErgoBoxCandidate>,
        inputs: Vec<Input>,
    ) -> (Vec<u8>, ErgoTransaction) {
        let tx = ErgoTransaction {
            inputs,
            data_inputs: vec![],
            output_candidates: outputs,
            tx_id: TxId(tx_id),
        };
        // tx_bytes can be arbitrary for testing; we use the tx_id from the
        // parsed transaction, not blake2b256(tx_bytes).
        let tx_bytes = tx_id.to_vec();
        (tx_bytes, tx)
    }

    fn make_output(value: u64, tree: Vec<u8>, tokens: Vec<(BoxId, u64)>) -> ErgoBoxCandidate {
        ErgoBoxCandidate {
            value,
            ergo_tree_bytes: tree,
            creation_height: 100,
            tokens,
            additional_registers: vec![],
        }
    }

    fn open_temp_db() -> (tempfile::TempDir, ExtraIndexerDb) {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        (tmp, db)
    }

    // -----------------------------------------------------------------------
    // Test 1: Empty block
    // -----------------------------------------------------------------------

    #[test]
    fn index_empty_block() {
        let (_tmp, db) = open_temp_db();
        let mut state = IndexerState {
            indexed_height: 0,
            global_tx_index: 0,
            global_box_index: 0,
        };
        let mut buffer = IndexerBuffer::new();

        index_block(&db, &mut state, &mut buffer, &[], 5).unwrap();

        // State updated to height but counters unchanged.
        assert_eq!(state.indexed_height, 5);
        assert_eq!(state.global_tx_index, 0);
        assert_eq!(state.global_box_index, 0);
        assert_eq!(buffer.mod_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Test 2: Single tx with 2 outputs
    // -----------------------------------------------------------------------

    #[test]
    fn index_single_tx_outputs() {
        let (_tmp, db) = open_temp_db();
        let mut state = IndexerState {
            indexed_height: 0,
            global_tx_index: 0,
            global_box_index: 0,
        };
        let mut buffer = IndexerBuffer::new();

        let ta = tree_a();
        let tb = tree_b();

        let (tx_bytes, tx) = make_test_tx(
            [0xAA; 32],
            vec![
                make_output(1_000_000_000, ta.clone(), vec![]),
                make_output(500_000_000, tb.clone(), vec![]),
            ],
            vec![],
        );

        // Index at height 1 (genesis -- inputs skipped).
        index_block(&db, &mut state, &mut buffer, &[(tx_bytes, tx)], 1).unwrap();

        assert_eq!(state.indexed_height, 1);
        assert_eq!(state.global_tx_index, 1);
        assert_eq!(state.global_box_index, 2);

        // Verify the tx is in the buffer.
        let tx_data = buffer.find(&[0xAA; 32]).unwrap();
        let indexed_tx = IndexedErgoTransaction::deserialize(tx_data).unwrap();
        assert_eq!(indexed_tx.tx_id, ModifierId([0xAA; 32]));
        assert_eq!(indexed_tx.index, 0);
        assert_eq!(indexed_tx.height, 1);
        assert_eq!(indexed_tx.global_index, 0);
        assert_eq!(indexed_tx.output_indexes, vec![0, 1]);

        // Verify boxes are in the buffer.
        let out0 = make_output(1_000_000_000, ta.clone(), vec![]);
        let out1 = make_output(500_000_000, tb.clone(), vec![]);
        let box_id_0 = compute_box_id(&out0, &TxId([0xAA; 32]), 0);
        let box_data = buffer.find(&box_id_0.0).unwrap();
        let indexed_box = IndexedErgoBox::deserialize(box_data).unwrap();
        assert_eq!(indexed_box.value, 1_000_000_000);
        assert_eq!(indexed_box.global_index, 0);
        assert_eq!(indexed_box.inclusion_height, 1);
        assert!(indexed_box.spending_tx_id.is_none());

        let box_id_1 = compute_box_id(&out1, &TxId([0xAA; 32]), 1);
        let box_data = buffer.find(&box_id_1.0).unwrap();
        let indexed_box = IndexedErgoBox::deserialize(box_data).unwrap();
        assert_eq!(indexed_box.value, 500_000_000);
        assert_eq!(indexed_box.global_index, 1);

        // Verify address entries exist.
        let addr_key_a = tree_hash_key(&ta);
        let addr_data = buffer.find(&addr_key_a).unwrap();
        let addr = IndexedErgoAddress::deserialize(addr_data).unwrap();
        assert_eq!(addr.balance.nano_ergs, 1_000_000_000);
        assert_eq!(addr.box_indexes, vec![0]);

        let addr_key_b = tree_hash_key(&tb);
        let addr_data = buffer.find(&addr_key_b).unwrap();
        let addr = IndexedErgoAddress::deserialize(addr_data).unwrap();
        assert_eq!(addr.balance.nano_ergs, 500_000_000);
        assert_eq!(addr.box_indexes, vec![1]);
    }

    // -----------------------------------------------------------------------
    // Test 3: Numeric indexes are created correctly
    // -----------------------------------------------------------------------

    #[test]
    fn index_creates_numeric_indexes() {
        let (_tmp, db) = open_temp_db();
        let mut state = IndexerState {
            indexed_height: 0,
            global_tx_index: 5,
            global_box_index: 10,
        };
        let mut buffer = IndexerBuffer::new();

        let ta = tree_a();
        let (tx_bytes, tx) = make_test_tx(
            [0xBB; 32],
            vec![make_output(100_000, ta.clone(), vec![])],
            vec![],
        );

        index_block(&db, &mut state, &mut buffer, &[(tx_bytes, tx)], 1).unwrap();

        // Check NumericBoxIndex at global_box_index=10.
        let nb_key = numeric_box_key(10);
        let nb_data = buffer.find(&nb_key).unwrap();
        let nb = NumericBoxIndex::deserialize(nb_data).unwrap();
        assert_eq!(nb.n, 10);
        let expected_box_id =
            compute_box_id(&make_output(100_000, ta, vec![]), &TxId([0xBB; 32]), 0);
        assert_eq!(nb.box_id, ModifierId(expected_box_id.0));

        // Check NumericTxIndex at global_tx_index=5.
        let nt_key = numeric_tx_key(5);
        let nt_data = buffer.find(&nt_key).unwrap();
        let nt = NumericTxIndex::deserialize(nt_data).unwrap();
        assert_eq!(nt.n, 5);
        assert_eq!(nt.tx_id, ModifierId([0xBB; 32]));

        // State incremented.
        assert_eq!(state.global_tx_index, 6);
        assert_eq!(state.global_box_index, 11);
    }

    // -----------------------------------------------------------------------
    // Test 4: Flush writes to DB
    // -----------------------------------------------------------------------

    #[test]
    fn flush_writes_to_db() {
        let (_tmp, db) = open_temp_db();
        let mut state = IndexerState {
            indexed_height: 0,
            global_tx_index: 0,
            global_box_index: 0,
        };
        let mut buffer = IndexerBuffer::new();

        let (tx_bytes, tx) = make_test_tx(
            [0xCC; 32],
            vec![make_output(999_999, tree_a(), vec![])],
            vec![],
        );

        index_block(&db, &mut state, &mut buffer, &[(tx_bytes, tx)], 1).unwrap();

        // Buffer has entries but DB is empty (below threshold).
        assert!(buffer.mod_count() > 0);
        let tx_key = [0xCC; 32];
        assert!(db.get(&tx_key).unwrap().is_none());

        // Flush manually.
        flush_buffer(&db, &state, &mut buffer).unwrap();

        // Now DB has the data.
        let tx_data = db.get(&tx_key).unwrap().unwrap();
        let indexed_tx = IndexedErgoTransaction::deserialize(&tx_data).unwrap();
        assert_eq!(indexed_tx.tx_id, ModifierId([0xCC; 32]));
        assert_eq!(indexed_tx.height, 1);

        // Progress counters persisted.
        assert_eq!(db.get_progress_u32(&indexed_height_key()).unwrap(), 1);
        assert_eq!(db.get_progress_u64(&global_tx_index_key()).unwrap(), 1);
        assert_eq!(db.get_progress_u64(&global_box_index_key()).unwrap(), 1);

        // Buffer is reset.
        assert_eq!(buffer.mod_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Test 5: Rollback removes indexed entries
    // -----------------------------------------------------------------------

    #[test]
    fn rollback_removes_indexed_entries() {
        let (_tmp, db) = open_temp_db();
        let mut state = IndexerState {
            indexed_height: 0,
            global_tx_index: 0,
            global_box_index: 0,
        };
        let mut buffer = IndexerBuffer::new();

        let ta = tree_a();

        // Block 1 (genesis): 1 tx with 1 output.
        let (tx1_bytes, tx1) = make_test_tx(
            [0x11; 32],
            vec![make_output(1_000_000_000, ta.clone(), vec![])],
            vec![],
        );
        index_block(&db, &mut state, &mut buffer, &[(tx1_bytes, tx1)], 1).unwrap();
        flush_buffer(&db, &state, &mut buffer).unwrap();

        let box1_id = compute_box_id(
            &make_output(1_000_000_000, ta.clone(), vec![]),
            &TxId([0x11; 32]),
            0,
        );

        // Block 2: 1 tx with 1 output.
        let (tx2_bytes, tx2) = make_test_tx(
            [0x22; 32],
            vec![make_output(500_000_000, ta.clone(), vec![])],
            vec![],
        );
        index_block(&db, &mut state, &mut buffer, &[(tx2_bytes, tx2)], 2).unwrap();
        flush_buffer(&db, &state, &mut buffer).unwrap();

        let box2_id = compute_box_id(
            &make_output(500_000_000, ta.clone(), vec![]),
            &TxId([0x22; 32]),
            0,
        );

        // Verify both are present before rollback.
        assert_eq!(state.indexed_height, 2);
        assert_eq!(state.global_tx_index, 2);
        assert_eq!(state.global_box_index, 2);
        assert!(db.get(&[0x11; 32]).unwrap().is_some()); // tx1
        assert!(db.get(&[0x22; 32]).unwrap().is_some()); // tx2
        assert!(db.get(&box1_id.0).unwrap().is_some());
        assert!(db.get(&box2_id.0).unwrap().is_some());

        // Rollback to height 1.
        remove_after(&db, &mut state, &mut buffer, 1).unwrap();

        // Block 1 entries should remain.
        assert!(db.get(&[0x11; 32]).unwrap().is_some());
        assert!(db.get(&box1_id.0).unwrap().is_some());
        assert!(db.get(&numeric_tx_key(0)).unwrap().is_some());
        assert!(db.get(&numeric_box_key(0)).unwrap().is_some());

        // Block 2 entries should be gone.
        assert!(db.get(&[0x22; 32]).unwrap().is_none());
        assert!(db.get(&box2_id.0).unwrap().is_none());
        assert!(db.get(&numeric_tx_key(1)).unwrap().is_none());
        assert!(db.get(&numeric_box_key(1)).unwrap().is_none());

        // Address should only have block 1's box.
        let addr_key = tree_hash_key(&ta);
        let addr_data = db.get(&addr_key).unwrap().unwrap();
        let addr = IndexedErgoAddress::deserialize(&addr_data).unwrap();
        assert_eq!(addr.balance.nano_ergs, 1_000_000_000);
        assert_eq!(addr.box_indexes, vec![0]); // only box 0 remains
    }

    // -----------------------------------------------------------------------
    // Test 6: Rollback restores spending info
    // -----------------------------------------------------------------------

    #[test]
    fn rollback_restores_spending_info() {
        let (_tmp, db) = open_temp_db();
        let mut state = IndexerState {
            indexed_height: 0,
            global_tx_index: 0,
            global_box_index: 0,
        };
        let mut buffer = IndexerBuffer::new();

        let ta = tree_a();

        // Block 1 (genesis): tx creates a box.
        let (tx1_bytes, tx1) = make_test_tx(
            [0x11; 32],
            vec![make_output(1_000_000_000, ta.clone(), vec![])],
            vec![],
        );
        index_block(&db, &mut state, &mut buffer, &[(tx1_bytes, tx1)], 1).unwrap();
        flush_buffer(&db, &state, &mut buffer).unwrap();

        let box1_id = compute_box_id(
            &make_output(1_000_000_000, ta.clone(), vec![]),
            &TxId([0x11; 32]),
            0,
        );

        // Verify the box is unspent.
        let box_data = db.get(&box1_id.0).unwrap().unwrap();
        let ibox = IndexedErgoBox::deserialize(&box_data).unwrap();
        assert!(ibox.spending_tx_id.is_none());
        assert!(ibox.spending_height.is_none());

        // Block 2: tx spends the box from block 1 and creates a new one.
        let (tx2_bytes, tx2) = make_test_tx(
            [0x22; 32],
            vec![make_output(900_000_000, ta.clone(), vec![])],
            vec![Input {
                box_id: BoxId(box1_id.0),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
        );
        index_block(&db, &mut state, &mut buffer, &[(tx2_bytes, tx2)], 2).unwrap();
        flush_buffer(&db, &state, &mut buffer).unwrap();

        // Verify the box is now spent.
        let box_data = db.get(&box1_id.0).unwrap().unwrap();
        let ibox = IndexedErgoBox::deserialize(&box_data).unwrap();
        assert_eq!(ibox.spending_tx_id, Some(ModifierId([0x22; 32])));
        assert_eq!(ibox.spending_height, Some(2));

        // Verify address balance was reduced (box spent, new box created).
        let addr_key = tree_hash_key(&ta);
        let addr_data = db.get(&addr_key).unwrap().unwrap();
        let addr = IndexedErgoAddress::deserialize(&addr_data).unwrap();
        // Balance should be 900M (box1 spent = -1B, box2 created = +900M).
        assert_eq!(addr.balance.nano_ergs, 900_000_000);

        // Rollback to height 1.
        remove_after(&db, &mut state, &mut buffer, 1).unwrap();

        // Box 1 should be unspent again.
        let box_data = db.get(&box1_id.0).unwrap().unwrap();
        let ibox = IndexedErgoBox::deserialize(&box_data).unwrap();
        assert!(ibox.spending_tx_id.is_none());
        assert!(ibox.spending_height.is_none());

        // Address balance should be restored to 1B.
        let addr_data = db.get(&addr_key).unwrap().unwrap();
        let addr = IndexedErgoAddress::deserialize(&addr_data).unwrap();
        assert_eq!(addr.balance.nano_ergs, 1_000_000_000);
        // Box index should be positive (unnegated).
        assert_eq!(addr.box_indexes, vec![0]);
    }

    // -----------------------------------------------------------------------
    // Test 7: Rollback updates progress
    // -----------------------------------------------------------------------

    #[test]
    fn rollback_updates_progress() {
        let (_tmp, db) = open_temp_db();
        let mut state = IndexerState {
            indexed_height: 0,
            global_tx_index: 0,
            global_box_index: 0,
        };
        let mut buffer = IndexerBuffer::new();

        let tree = tree_b();

        // Index 3 blocks with 1 tx each, 1 output each.
        for height in 1..=3u32 {
            let mut tx_id = [0u8; 32];
            tx_id[0] = height as u8;
            let (tx_bytes, tx) = make_test_tx(
                tx_id,
                vec![make_output(100_000 * height as u64, tree.clone(), vec![])],
                vec![],
            );
            // Use height=1 as genesis.
            index_block(&db, &mut state, &mut buffer, &[(tx_bytes, tx)], height).unwrap();
        }
        flush_buffer(&db, &state, &mut buffer).unwrap();

        // Before rollback.
        assert_eq!(state.indexed_height, 3);
        assert_eq!(state.global_tx_index, 3);
        assert_eq!(state.global_box_index, 3);
        assert_eq!(db.get_progress_u32(&indexed_height_key()).unwrap(), 3);
        assert_eq!(db.get_progress_u64(&global_tx_index_key()).unwrap(), 3);
        assert_eq!(db.get_progress_u64(&global_box_index_key()).unwrap(), 3);

        // Rollback to height 1.
        remove_after(&db, &mut state, &mut buffer, 1).unwrap();

        // State should reflect height 1.
        assert_eq!(state.indexed_height, 1);
        assert_eq!(state.global_tx_index, 1);
        assert_eq!(state.global_box_index, 1);

        // Progress counters in DB should also reflect height 1.
        assert_eq!(db.get_progress_u32(&indexed_height_key()).unwrap(), 1);
        assert_eq!(db.get_progress_u64(&global_tx_index_key()).unwrap(), 1);
        assert_eq!(db.get_progress_u64(&global_box_index_key()).unwrap(), 1);
    }
}
