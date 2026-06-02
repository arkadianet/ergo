//! Lock-free read handle to chain state for concurrent readers.
//!
//! Cloning a `ChainStoreReader` is cheap — it shares the same redb
//! `Database` via `Arc`. Each method opens a fresh read transaction, so
//! holders can read in parallel without coordination.
//!
//! Trade-off vs. `StateStore`'s read methods: this handle does **not**
//! see writes that are buffered in `batch_headers` / `batch_meta` and
//! not yet committed. Readers may briefly miss the very-tip header
//! during the window between batch buffering and commit. For id-keyed
//! lookups against historical heights this is irrelevant; for tip-only
//! reads, prefer the snapshot path.

use std::sync::Arc;

use redb::Database;

use crate::avl::node::NULL_NODE;
use crate::chain::{ChainStateMeta, HeaderMeta};
use crate::store::{
    read_height_index_ids, CommittedSnapshot, StateError, AVL_NODES, BLOCK_SECTIONS,
    CHAIN_STATE_META, HEADERS, HEADERS_BY_HEIGHT, HEADER_CHAIN_INDEX, HEADER_META,
    MODIFIER_TYPE_INDEX, STATE_META,
};

/// Lock-free read handle over the chain state. Cloning is cheap — the
/// underlying redb [`Database`] is shared via `Arc`, and every method
/// opens its own read transaction so concurrent readers are
/// independent.
#[derive(Clone)]
pub struct ChainStoreReader {
    db: Arc<Database>,
}

impl ChainStoreReader {
    /// Construct from an `Arc<Database>` shared with the owning
    /// [`crate::store::StateStore`]. Crate-private so external callers
    /// always go through `StateStore::reader()`.
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Public constructor for callers that already hold an `Arc<Database>`
    /// (e.g. the wallet writer task's `ChainStateAccessorImpl`, which holds
    /// `Arc<redb::Database>` from `StateStore::db_arc()`).
    pub fn new_from_db(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Open a [`CommittedSnapshot`] over the committed (durable) state — the
    /// single-read-transaction view the off-loop mining-candidate engine
    /// builds from. Returns `Ok(None)` for a store with no committed state.
    ///
    /// This is the off-loop opener (the `StateStore::committed_snapshot`
    /// twin) usable from any holder of this cheap `Clone + Send + Sync`
    /// handle. The snapshot reflects the last redb commit, which can trail
    /// the in-memory applied tip by the persist-pipeline depth; callers
    /// compare `best_full_block_id()` to their expected parent and retry.
    pub fn committed_snapshot(&self) -> Result<Option<CommittedSnapshot>, StateError> {
        CommittedSnapshot::open(&self.db)
    }

    /// Committed best-full-block tip, read directly from `chain_state_meta`.
    ///
    /// Returns `None` when no chain has been written yet (fresh DB pre-genesis,
    /// or the table hasn't been materialized). The reader path opens its own
    /// fresh redb txn — matching the rest of this struct's snapshot caveat.
    /// Used by the indexer's chain-source adapter to drive its tip-poll.
    pub fn committed_tip(&self) -> Result<Option<(u32, [u8; 32])>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(CHAIN_STATE_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let bytes = match table.get("chain_state")? {
            Some(g) => g.value().to_vec(),
            None => return Ok(None),
        };
        let meta = ChainStateMeta::deserialize(&bytes).map_err(|e| StateError::DbCorruption {
            table: "chain_state_meta",
            key: hex::encode(b"chain_state"),
            reason: format!("decode: {e}"),
        })?;
        Ok(Some((meta.best_full_block_height, meta.best_full_block_id)))
    }

    /// Every header id known at a given height — best chain plus any
    /// validated orphans. Backs the Scala-compat `/blocks/at/{h}`
    /// route. First entry (when non-empty) is always the best-chain
    /// header id at `height`; subsequent entries are orphans.
    /// Mirrors Scala's `headerIdsAtHeight` in
    /// `HeadersProcessor.scala:274` and the [`HEADERS_BY_HEIGHT`]
    /// invariant documented on the table definition.
    pub fn header_ids_at_height_all(&self, height: u32) -> Result<Vec<[u8; 32]>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(HEADERS_BY_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        read_height_index_ids(&table, height)
    }

    /// Header ID on the canonical best-header chain at `height`. Returns
    /// `None` if the height is past the tip or no chain has been written.
    pub fn get_header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(HEADER_CHAIN_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(height as u64)? {
            Some(guard) => {
                let bytes = guard.value();
                if bytes.len() != 32 {
                    return Err(StateError::DbCorruption {
                        table: "header_chain_index",
                        key: hex::encode((height as u64).to_be_bytes()),
                        reason: format!("row has len {} (expected 32)", bytes.len()),
                    });
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(bytes);
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    /// Active voted-protocol parameters at `height` — the latest row in
    /// `voted_params` with key `≤ height`. `Ok(None)` when the table is
    /// empty (boot before genesis); after init the genesis row at key 0
    /// is always present, so post-init callers can treat `None` as a
    /// bug. Mirrors `StateStore::active_params_at` for read-only callers
    /// (`ergo-api` bridge) that hold a `ChainStoreReader`, not a
    /// `StateStore`.
    pub fn active_params_at(
        &self,
        height: u32,
    ) -> Result<Option<ergo_validation::ActiveProtocolParameters>, StateError> {
        let r = self.db.begin_read()?;
        Ok(crate::active_params::read_latest_at(&r, height)?)
    }

    /// Serialized header bytes by header_id. Returns `None` if not present.
    /// Does not see headers that are still in `batch_headers` and not yet
    /// committed — sufficient for id-keyed historical lookups.
    pub fn get_header(&self, header_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(HEADERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(header_id.as_slice())? {
            Some(guard) => Ok(Some(guard.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Look up the modifier-type byte for a given id. Returns one of
    /// 101 (Header), 102 (BlockTransactions), 104 (ADProofs), 108
    /// (Extension), or `None` for unknown / pre-back-fill ids.
    pub fn get_modifier_type(&self, id: &[u8; 32]) -> Result<Option<u8>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(MODIFIER_TYPE_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(id.as_slice())? {
            Some(g) => Ok(Some(g.value())),
            None => Ok(None),
        }
    }

    /// Serialized block-section bytes by modifier_id (NOT header_id).
    /// Section IDs come from `ergo_ser::modifier_id::ExpectedSections`.
    pub fn get_block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(BLOCK_SECTIONS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(modifier_id.as_slice())? {
            Some(guard) => Ok(Some(guard.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Scan a contiguous slice of `(height, header_id)` from the canonical
    /// best-header chain. Inclusive of both `lo` and `hi`; returns an empty
    /// vec if `hi < lo` or the range falls past the tip. Same caveat as
    /// `get_header_id_at_height`: does not see in-flight `batch_headers` writes.
    pub fn scan_header_chain_range(
        &self,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<(u32, [u8; 32])>, StateError> {
        if hi < lo {
            return Ok(Vec::new());
        }
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(HEADER_CHAIN_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::with_capacity((hi - lo + 1) as usize);
        for entry in table.range(lo as u64..=hi as u64)? {
            let (k, v) = entry?;
            let bytes = v.value();
            if bytes.len() != 32 {
                return Err(StateError::DbCorruption {
                    table: "header_chain_index",
                    key: hex::encode(k.value().to_be_bytes()),
                    reason: format!("row has len {} (expected 32)", bytes.len()),
                });
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(bytes);
            out.push((k.value() as u32, id));
        }
        Ok(out)
    }

    /// Header metadata by header_id (parent, height, score, validity).
    pub fn get_header_meta(&self, header_id: &[u8; 32]) -> Result<Option<HeaderMeta>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(HEADER_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(header_id.as_slice())? {
            Some(guard) => HeaderMeta::deserialize(guard.value())
                .map(Some)
                .map_err(|e| StateError::DbCorruption {
                    table: "header_meta",
                    key: hex::encode(header_id),
                    reason: e.to_string(),
                }),
            None => Ok(None),
        }
    }

    /// Lookup a box by box_id from the committed UTXO set, walking the
    /// AVL+ tree directly via redb. Returns the canonical serialized box
    /// bytes (no reserialization) or `None` if the box isn't committed.
    ///
    /// Uses a single `ReadTransaction` for both `STATE_META` and
    /// `AVL_NODES` so the walk is snapshot-consistent: mixing a newer
    /// tree's meta with an older snapshot's nodes (or vice versa) could
    /// otherwise produce false hits or false misses across a commit
    /// boundary.
    ///
    /// Returns `Ok(None)` when there is no committed state, the tree
    /// root is `NULL_NODE`, or the key is absent. Returns `Err` only on
    /// physical corruption: malformed `StateMeta` row, malformed AVL
    /// node bytes, unknown node tag, an internal node referencing a
    /// missing or null child, or a missing `AVL_NODES` table when
    /// `STATE_META` advertises a non-zero root.
    ///
    /// Does NOT consult the mempool — that overlay belongs to a
    /// higher-level seam.
    pub fn lookup_box(&self, box_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        let read_txn = self.db.begin_read()?;

        let meta_table = match read_txn.open_table(STATE_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let meta_bytes = match meta_table.get("root")? {
            Some(g) => g.value().to_vec(),
            None => return Ok(None),
        };
        if meta_bytes.len() != 46 {
            return Err(StateError::DbCorruption {
                table: "state_meta",
                key: hex::encode(b"root"),
                reason: format!("row has len {} (expected 46)", meta_bytes.len()),
            });
        }
        let root_node_id = u64::from_be_bytes(meta_bytes[38..46].try_into().unwrap());
        lookup_box_in_txn(&read_txn, root_node_id, box_id)
    }
}

/// Single-box descent over the committed AVL+ within ONE read transaction.
///
/// Shared by [`ChainStoreReader::lookup_box`] (fresh per-call txn) and
/// `CommittedSnapshot::lookup_box` (the snapshot's one held txn) so both
/// resolve a box id **byte-identically** — same `parse_walk_node` descent,
/// which deliberately ignores the balance / child-label bytes that are
/// irrelevant to a key-ordered descent (a stricter parser like
/// `node_from_bytes` would reject a malformed-but-descendable node that this
/// path still walks). `root_node_id` is the committed AVL root for the view.
/// `Ok(None)` for an empty tree or absent key; `Err(DbCorruption)` for a
/// missing/malformed node or a null internal child.
pub(crate) fn lookup_box_in_txn(
    read_txn: &redb::ReadTransaction,
    root_node_id: u64,
    box_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, StateError> {
    if root_node_id == NULL_NODE {
        return Ok(None);
    }
    let nodes_table = match read_txn.open_table(AVL_NODES) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(StateError::DbCorruption {
                table: "avl_nodes",
                key: hex::encode(root_node_id.to_be_bytes()),
                reason: format!(
                    "table missing but state_meta advertises root_node_id={root_node_id}"
                ),
            });
        }
        Err(e) => return Err(e.into()),
    };
    let mut id = root_node_id;
    loop {
        let guard = nodes_table
            .get(id)?
            .ok_or_else(|| StateError::DbCorruption {
                table: "avl_nodes",
                key: hex::encode(id.to_be_bytes()),
                reason: format!("missing node id {id} during walk"),
            })?;
        let node = parse_walk_node(guard.value())?;
        drop(guard);
        match node {
            WalkNode::Leaf {
                key: leaf_key,
                value,
            } => {
                return Ok(if &leaf_key == box_id {
                    Some(value)
                } else {
                    None
                });
            }
            WalkNode::Internal {
                sep_key,
                left,
                right,
            } => {
                let next = if box_id < &sep_key { left } else { right };
                if next == NULL_NODE {
                    return Err(StateError::DbCorruption {
                        table: "avl_nodes",
                        key: hex::encode(id.to_be_bytes()),
                        reason: format!("internal node id {id} has null child"),
                    });
                }
                id = next;
            }
        }
    }
}

/// Minimal AVL-node view for the read-only lookup walk: only the fields
/// needed to descend or terminate. Decouples the reader from `AvlNode`
/// and avoids hydrating labels we never consult.
enum WalkNode {
    Leaf {
        key: [u8; 32],
        value: Vec<u8>,
    },
    Internal {
        sep_key: [u8; 32],
        left: u64,
        right: u64,
    },
}

/// Defensive parser mirroring `crate::store::node_from_bytes` but
/// returning `Err` on malformed input instead of panicking. The reader
/// path must surface corruption as an error, never silently as a miss.
fn parse_walk_node(data: &[u8]) -> Result<WalkNode, StateError> {
    let bad = |msg: String| StateError::Serialization(msg);
    let tag = *data
        .first()
        .ok_or_else(|| bad("avl node: empty bytes".to_string()))?;
    match tag {
        0x00 => {
            if data.len() < 37 {
                return Err(bad(format!(
                    "avl node leaf: header truncated ({} bytes, need >=37)",
                    data.len()
                )));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[1..33]);
            let value_len = u32::from_be_bytes(data[33..37].try_into().unwrap()) as usize;
            let value_end = 37usize
                .checked_add(value_len)
                .ok_or_else(|| bad(format!("avl node leaf: value_len overflow ({value_len})")))?;
            let next_key_end = value_end
                .checked_add(32)
                .ok_or_else(|| bad("avl node leaf: next_key offset overflow".to_string()))?;
            if data.len() < next_key_end {
                return Err(bad(format!(
                    "avl node leaf: body truncated (have {}, need >={} for value_len={})",
                    data.len(),
                    next_key_end,
                    value_len
                )));
            }
            let value = data[37..value_end].to_vec();
            Ok(WalkNode::Leaf { key, value })
        }
        0x01 => {
            if data.len() < 50 {
                return Err(bad(format!(
                    "avl node v1 internal: truncated ({} bytes, need >=50)",
                    data.len()
                )));
            }
            let mut sep_key = [0u8; 32];
            sep_key.copy_from_slice(&data[1..33]);
            let left = u64::from_be_bytes(data[33..41].try_into().unwrap());
            let right = u64::from_be_bytes(data[41..49].try_into().unwrap());
            Ok(WalkNode::Internal {
                sep_key,
                left,
                right,
            })
        }
        0x02 => {
            if data.len() < 114 {
                return Err(bad(format!(
                    "avl node v2 internal: truncated ({} bytes, need >=114)",
                    data.len()
                )));
            }
            let mut sep_key = [0u8; 32];
            sep_key.copy_from_slice(&data[1..33]);
            let left = u64::from_be_bytes(data[33..41].try_into().unwrap());
            let right = u64::from_be_bytes(data[41..49].try_into().unwrap());
            Ok(WalkNode::Internal {
                sep_key,
                left,
                right,
            })
        }
        other => Err(bad(format!("avl node: unknown tag 0x{other:02x}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::Database;
    use tempfile::TempDir;

    // ----- helpers -----

    fn fresh_db() -> (TempDir, Arc<Database>) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.redb");
        let db = Arc::new(Database::create(&path).unwrap());
        (dir, db)
    }

    fn write_state_meta(db: &Arc<Database>, root_node_id: u64) {
        let mut meta = vec![0u8; 46];
        meta[38..46].copy_from_slice(&root_node_id.to_be_bytes());
        let txn = crate::begin_write_qr(db).unwrap();
        {
            let mut t = txn.open_table(STATE_META).unwrap();
            t.insert("root", meta.as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }

    fn write_state_meta_raw(db: &Arc<Database>, raw: &[u8]) {
        let txn = crate::begin_write_qr(db).unwrap();
        {
            let mut t = txn.open_table(STATE_META).unwrap();
            t.insert("root", raw).unwrap();
        }
        txn.commit().unwrap();
    }

    fn write_chain_state_meta_raw(db: &Arc<Database>, raw: &[u8]) {
        let txn = crate::begin_write_qr(db).unwrap();
        {
            let mut t = txn.open_table(CHAIN_STATE_META).unwrap();
            t.insert("chain_state", raw).unwrap();
        }
        txn.commit().unwrap();
    }

    fn write_header_chain_index_raw(db: &Arc<Database>, height: u32, raw: &[u8]) {
        let txn = crate::begin_write_qr(db).unwrap();
        {
            let mut t = txn.open_table(HEADER_CHAIN_INDEX).unwrap();
            t.insert(height as u64, raw).unwrap();
        }
        txn.commit().unwrap();
    }

    fn write_node(db: &Arc<Database>, id: u64, bytes: &[u8]) {
        let txn = crate::begin_write_qr(db).unwrap();
        {
            let mut t = txn.open_table(AVL_NODES).unwrap();
            t.insert(id, bytes).unwrap();
        }
        txn.commit().unwrap();
    }

    fn leaf_bytes(key: &[u8; 32], value: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 4 + value.len() + 32);
        buf.push(0x00);
        buf.extend_from_slice(key);
        buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buf.extend_from_slice(value);
        buf.extend_from_slice(&[0u8; 32]); // next_key (unused by lookup)
        buf
    }

    fn internal_v2_bytes(sep_key: &[u8; 32], left: u64, right: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(114);
        buf.push(0x02);
        buf.extend_from_slice(sep_key);
        buf.extend_from_slice(&left.to_be_bytes());
        buf.extend_from_slice(&right.to_be_bytes());
        buf.push(0); // balance
        buf.extend_from_slice(&[0u8; 32]); // left_label (unused by lookup)
        buf.extend_from_slice(&[0u8; 32]); // right_label
        buf
    }

    fn assert_serialization_err(r: Result<Option<Vec<u8>>, StateError>, needle: &str) {
        match r {
            Err(StateError::Serialization(msg)) => assert!(
                msg.contains(needle),
                "expected message containing {needle:?}, got: {msg}"
            ),
            other => panic!("expected Serialization Err with {needle:?}, got {other:?}"),
        }
    }

    fn assert_db_corruption<T>(
        r: Result<T, StateError>,
        expected_table: &'static str,
        expected_key: String,
        reason_needle: &str,
    ) {
        match r {
            Err(StateError::DbCorruption { table, key, reason }) => {
                assert_eq!(table, expected_table);
                assert_eq!(key, expected_key);
                assert!(
                    reason.contains(reason_needle),
                    "expected reason containing {reason_needle:?}, got: {reason}"
                );
            }
            Err(other) => panic!("expected DbCorruption Err with {reason_needle:?}, got {other:?}"),
            Ok(_) => panic!("expected DbCorruption Err with {reason_needle:?}, got Ok(_)"),
        }
    }

    // ----- happy path -----

    #[test]
    fn empty_db_lookup_returns_none() {
        let (_dir, db) = fresh_db();
        let reader = ChainStoreReader::new(db);
        assert_eq!(reader.lookup_box(&[0xAA; 32]).unwrap(), None);
    }

    #[test]
    fn empty_state_meta_table_returns_none() {
        let (_dir, db) = fresh_db();
        // Materialize the table without writing "root".
        let txn = crate::begin_write_qr(&db).unwrap();
        {
            let _ = txn.open_table(STATE_META).unwrap();
        }
        txn.commit().unwrap();
        let reader = ChainStoreReader::new(db);
        assert_eq!(reader.lookup_box(&[0xAA; 32]).unwrap(), None);
    }

    #[test]
    fn null_root_node_id_returns_none() {
        let (_dir, db) = fresh_db();
        write_state_meta(&db, NULL_NODE);
        let reader = ChainStoreReader::new(db);
        assert_eq!(reader.lookup_box(&[0xAA; 32]).unwrap(), None);
    }

    #[test]
    fn happy_path_single_leaf_hit_and_miss() {
        let (_dir, db) = fresh_db();
        let key = [0xABu8; 32];
        let value = b"box-bytes".to_vec();
        write_state_meta(&db, 1);
        write_node(&db, 1, &leaf_bytes(&key, &value));

        let reader = ChainStoreReader::new(db);
        assert_eq!(reader.lookup_box(&key).unwrap(), Some(value));
        let miss = [0xCDu8; 32];
        assert_eq!(reader.lookup_box(&miss).unwrap(), None);
    }

    #[test]
    fn happy_path_internal_steers_correctly() {
        let (_dir, db) = fresh_db();
        // Tree:
        //   root id=1: Internal sep=K_HI, left=2, right=3
        //   id=2: Leaf K_LO -> v_lo
        //   id=3: Leaf K_HI -> v_hi
        // For lookup(K_LO): K_LO < K_HI -> left -> leaf 2.
        // For lookup(K_HI): K_HI >= K_HI -> right -> leaf 3.
        let k_lo = [0x10u8; 32];
        let k_hi = [0xF0u8; 32];
        let v_lo = b"low".to_vec();
        let v_hi = b"high".to_vec();

        write_state_meta(&db, 1);
        // One write txn so all three nodes commit together.
        let txn = crate::begin_write_qr(&db).unwrap();
        {
            let mut t = txn.open_table(AVL_NODES).unwrap();
            t.insert(1u64, internal_v2_bytes(&k_hi, 2, 3).as_slice())
                .unwrap();
            t.insert(2u64, leaf_bytes(&k_lo, &v_lo).as_slice()).unwrap();
            t.insert(3u64, leaf_bytes(&k_hi, &v_hi).as_slice()).unwrap();
        }
        txn.commit().unwrap();

        let reader = ChainStoreReader::new(db);
        assert_eq!(reader.lookup_box(&k_lo).unwrap(), Some(v_lo));
        assert_eq!(reader.lookup_box(&k_hi).unwrap(), Some(v_hi));
        let mut miss = [0u8; 32];
        miss[0] = 0x05; // < k_hi -> left -> leaf 2 (k_lo) -> mismatch -> None
        assert_eq!(reader.lookup_box(&miss).unwrap(), None);
    }

    // ----- round-trips -----

    // ----- error paths -----

    #[test]
    fn committed_tip_malformed_chain_state_meta_returns_db_corruption() {
        let (_dir, db) = fresh_db();
        write_chain_state_meta_raw(&db, &[0u8; 10]);
        let reader = ChainStoreReader::new(db);
        // 10 bytes is short of the 32-byte best_header_id; the typed
        // truncation error surfaces that field name + the total length
        // through the DbCorruption envelope.
        assert_db_corruption(
            reader.committed_tip(),
            "chain_state_meta",
            hex::encode(b"chain_state"),
            "truncated at field `best_header_id`",
        );
    }

    #[test]
    fn get_header_id_at_height_malformed_row_returns_db_corruption() {
        let (_dir, db) = fresh_db();
        write_header_chain_index_raw(&db, 7, &[0xAA; 31]);
        let reader = ChainStoreReader::new(db);
        assert_db_corruption(
            reader.get_header_id_at_height(7),
            "header_chain_index",
            hex::encode(7u64.to_be_bytes()),
            "expected 32",
        );
    }

    #[test]
    fn scan_header_chain_range_malformed_row_returns_db_corruption() {
        let (_dir, db) = fresh_db();
        write_header_chain_index_raw(&db, 8, &[0xBB; 31]);
        let reader = ChainStoreReader::new(db);
        assert_db_corruption(
            reader.scan_header_chain_range(7, 9),
            "header_chain_index",
            hex::encode(8u64.to_be_bytes()),
            "expected 32",
        );
    }

    #[test]
    fn malformed_state_meta_returns_err() {
        let (_dir, db) = fresh_db();
        write_state_meta_raw(&db, &[0u8; 10]);
        let reader = ChainStoreReader::new(db);
        assert_db_corruption(
            reader.lookup_box(&[0xAA; 32]),
            "state_meta",
            hex::encode(b"root"),
            "expected 46",
        );
    }

    #[test]
    fn avl_table_missing_with_root_returns_err() {
        let (_dir, db) = fresh_db();
        write_state_meta(&db, 7);
        let reader = ChainStoreReader::new(db);
        assert_db_corruption(
            reader.lookup_box(&[0xAA; 32]),
            "avl_nodes",
            hex::encode(7u64.to_be_bytes()),
            "table missing",
        );
    }

    #[test]
    fn missing_avl_node_returns_err() {
        let (_dir, db) = fresh_db();
        write_state_meta(&db, 42);
        // Materialize the table but leave id=42 absent.
        let txn = crate::begin_write_qr(&db).unwrap();
        {
            let _ = txn.open_table(AVL_NODES).unwrap();
        }
        txn.commit().unwrap();
        let reader = ChainStoreReader::new(db);
        assert_db_corruption(
            reader.lookup_box(&[0xAA; 32]),
            "avl_nodes",
            hex::encode(42u64.to_be_bytes()),
            "missing node id 42",
        );
    }

    #[test]
    fn unknown_node_tag_returns_err() {
        let (_dir, db) = fresh_db();
        write_state_meta(&db, 1);
        write_node(&db, 1, &[0xFF]);
        let reader = ChainStoreReader::new(db);
        assert_serialization_err(reader.lookup_box(&[0xAA; 32]), "unknown tag");
    }

    #[test]
    fn truncated_leaf_returns_err() {
        let (_dir, db) = fresh_db();
        write_state_meta(&db, 1);
        write_node(&db, 1, &[0x00]); // tag 0x00 only
        let reader = ChainStoreReader::new(db);
        assert_serialization_err(reader.lookup_box(&[0xAA; 32]), "truncated");
    }

    #[test]
    fn truncated_internal_v2_returns_err() {
        let (_dir, db) = fresh_db();
        write_state_meta(&db, 1);
        write_node(&db, 1, &[0x02; 50]); // v2 needs 114 bytes
        let reader = ChainStoreReader::new(db);
        assert_serialization_err(reader.lookup_box(&[0xAA; 32]), "v2 internal");
    }

    #[test]
    fn internal_pointing_to_null_child_returns_err() {
        let (_dir, db) = fresh_db();
        write_state_meta(&db, 1);
        let sep = [0x80u8; 32];
        // Internal with right=NULL_NODE; lookup of key >= sep descends to NULL.
        write_node(&db, 1, &internal_v2_bytes(&sep, 2, NULL_NODE));
        // Provide a left leaf so the left-side path doesn't error first.
        write_node(&db, 2, &leaf_bytes(&[0u8; 32], b"x"));

        let reader = ChainStoreReader::new(db);
        let high_key = [0xFFu8; 32]; // >= sep -> right -> NULL_NODE
        assert_db_corruption(
            reader.lookup_box(&high_key),
            "avl_nodes",
            hex::encode(1u64.to_be_bytes()),
            "null child",
        );
    }

    // ----- oracle parity -----
}
