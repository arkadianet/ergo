//! Snapshot format: manifest and chunk serialization for UTXO set snapshots.
//!
//! The snapshot format splits a UTXO set into:
//! - A **manifest** (index) containing the height, AVL tree root digest, and
//!   blake2b256 IDs of each chunk.
//! - **Chunks** (data) each containing a batch of key-value entries up to ~1 MB.

use std::sync::Arc;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ergo_storage::node_db::NodeDb;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Target size in bytes for each snapshot chunk (~1 MB).
const CHUNK_TARGET_BYTES: usize = 1_000_000;

/// A snapshot entry: 32-byte key and variable-length value.
pub type SnapshotEntry = ([u8; 32], Vec<u8>);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during snapshot serialization / deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// The input data is too short to contain the expected fields.
    TruncatedData(&'static str),
    /// A length field exceeds the remaining data.
    InvalidLength(&'static str),
    /// Storage (RocksDB) error.
    Storage(String),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::TruncatedData(msg) => write!(f, "truncated data: {msg}"),
            SnapshotError::InvalidLength(msg) => write!(f, "invalid length: {msg}"),
            SnapshotError::Storage(msg) => write!(f, "storage error: {msg}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

// ---------------------------------------------------------------------------
// blake2b256 helper
// ---------------------------------------------------------------------------

/// Compute the Blake2b-256 hash of `data`, returning a 32-byte digest.
pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("correct length");
    out
}

// ---------------------------------------------------------------------------
// SnapshotManifest
// ---------------------------------------------------------------------------

/// A snapshot manifest indexes the chunks that make up a UTXO set snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotManifest {
    /// Block height at which the snapshot was taken.
    pub height: u32,
    /// AVL+ tree root digest (33 bytes).
    pub digest: [u8; 33],
    /// Blake2b-256 hash of each chunk's serialized bytes.
    pub chunk_ids: Vec<[u8; 32]>,
    /// Total number of UTXO entries across all chunks.
    pub total_entries: u64,
}

impl SnapshotManifest {
    /// Deterministic manifest identifier = blake2b256(serialize()).
    pub fn manifest_id(&self) -> [u8; 32] {
        blake2b256(&self.serialize())
    }

    /// Serialize to bytes.
    ///
    /// Format (all integers big-endian):
    /// ```text
    /// u32   height
    /// [u8; 33] digest
    /// u32   chunk_count
    /// N * [u8; 32] chunk_ids
    /// u64   total_entries
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let chunk_count = self.chunk_ids.len() as u32;
        let size = 4 + 33 + 4 + (chunk_count as usize) * 32 + 8;
        let mut buf = Vec::with_capacity(size);

        buf.extend_from_slice(&self.height.to_be_bytes());
        buf.extend_from_slice(&self.digest);
        buf.extend_from_slice(&chunk_count.to_be_bytes());
        for id in &self.chunk_ids {
            buf.extend_from_slice(id);
        }
        buf.extend_from_slice(&self.total_entries.to_be_bytes());

        buf
    }

    /// Deserialize from bytes produced by [`serialize`](Self::serialize).
    pub fn deserialize(data: &[u8]) -> Result<Self, SnapshotError> {
        // Minimum: 4 (height) + 33 (digest) + 4 (chunk_count) + 8 (total_entries) = 49
        if data.len() < 49 {
            return Err(SnapshotError::TruncatedData("manifest too short"));
        }

        let height = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        let mut digest = [0u8; 33];
        digest.copy_from_slice(&data[4..37]);

        let chunk_count = u32::from_be_bytes([data[37], data[38], data[39], data[40]]) as usize;

        let chunks_end = 41 + chunk_count * 32;
        if data.len() < chunks_end + 8 {
            return Err(SnapshotError::TruncatedData(
                "manifest too short for chunk_ids + total_entries",
            ));
        }

        let mut chunk_ids = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            let start = 41 + i * 32;
            let mut id = [0u8; 32];
            id.copy_from_slice(&data[start..start + 32]);
            chunk_ids.push(id);
        }

        let te_start = chunks_end;
        let total_entries = u64::from_be_bytes([
            data[te_start],
            data[te_start + 1],
            data[te_start + 2],
            data[te_start + 3],
            data[te_start + 4],
            data[te_start + 5],
            data[te_start + 6],
            data[te_start + 7],
        ]);

        Ok(SnapshotManifest {
            height,
            digest,
            chunk_ids,
            total_entries,
        })
    }
}

// ---------------------------------------------------------------------------
// SnapshotsInfo (P2P)
// ---------------------------------------------------------------------------

/// Lightweight listing of available snapshots, exchanged over P2P.
///
/// Each entry is a `(height, manifest_id)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotsInfo {
    pub manifests: Vec<(u32, [u8; 32])>,
}

impl SnapshotsInfo {
    /// Serialize for P2P transmission.
    ///
    /// Format (big-endian):
    /// ```text
    /// u32  count
    /// N * (i32 height + [u8; 32] manifest_id)
    /// ```
    pub fn serialize_p2p(&self) -> Vec<u8> {
        let count = self.manifests.len() as u32;
        let mut buf = Vec::with_capacity(4 + self.manifests.len() * 36);
        buf.extend_from_slice(&count.to_be_bytes());
        for (height, mid) in &self.manifests {
            buf.extend_from_slice(&(*height as i32).to_be_bytes());
            buf.extend_from_slice(mid);
        }
        buf
    }

    /// Deserialize from P2P bytes produced by [`serialize_p2p`](Self::serialize_p2p).
    pub fn deserialize_p2p(data: &[u8]) -> Result<Self, SnapshotError> {
        if data.len() < 4 {
            return Err(SnapshotError::TruncatedData("snapshots info too short"));
        }
        let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let expected = 4 + count * 36;
        if data.len() < expected {
            return Err(SnapshotError::TruncatedData(
                "snapshots info too short for entries",
            ));
        }
        let mut manifests = Vec::with_capacity(count);
        for i in 0..count {
            let base = 4 + i * 36;
            let h = i32::from_be_bytes([data[base], data[base + 1], data[base + 2], data[base + 3]])
                as u32;
            let mut mid = [0u8; 32];
            mid.copy_from_slice(&data[base + 4..base + 36]);
            manifests.push((h, mid));
        }
        Ok(SnapshotsInfo { manifests })
    }
}

// ---------------------------------------------------------------------------
// SnapshotsDb — persistent RocksDB storage
// ---------------------------------------------------------------------------

/// Key prefixes in the snapshots RocksDB.
const PREFIX_MANIFEST: u8 = 0x01;
const PREFIX_CHUNK: u8 = 0x02;
const INFO_KEY: &[u8] = &[0x00];

/// Persistent storage for UTXO set snapshots (manifests + chunks).
pub struct SnapshotsDb {
    db: Arc<NodeDb>,
}

impl SnapshotsDb {
    /// Open or create a SnapshotsDb at the given path.
    ///
    /// Creates its own `NodeDb`. Useful for standalone use or tests.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, SnapshotError> {
        let node_db = NodeDb::open(path).map_err(|e| SnapshotError::Storage(e.to_string()))?;
        Ok(Self {
            db: Arc::new(node_db),
        })
    }

    /// Wraps a shared `NodeDb`, using the `CF_SNAPSHOTS` column family.
    pub fn from_shared(db: Arc<NodeDb>) -> Self {
        Self { db }
    }

    /// Store a complete snapshot: manifest + all chunks.
    ///
    /// Also updates the `SnapshotsInfo` to include this manifest.
    pub fn store_snapshot(
        &self,
        manifest: &SnapshotManifest,
        chunks: &[([u8; 32], Vec<u8>)],
    ) -> Result<(), SnapshotError> {
        let manifest_id = manifest.manifest_id();
        let manifest_bytes = manifest.serialize();

        let cf = self.db.cf_snapshots();
        let mut batch = rocksdb::WriteBatch::default();

        // Store manifest keyed by PREFIX_MANIFEST ++ manifest_id.
        let mut manifest_key = vec![PREFIX_MANIFEST];
        manifest_key.extend_from_slice(&manifest_id);
        batch.put_cf(&cf, &manifest_key, &manifest_bytes);

        // Store each chunk keyed by PREFIX_CHUNK ++ chunk_id.
        for (chunk_id, chunk_data) in chunks {
            let mut chunk_key = vec![PREFIX_CHUNK];
            chunk_key.extend_from_slice(chunk_id);
            batch.put_cf(&cf, &chunk_key, chunk_data);
        }

        // Update SnapshotsInfo to include this manifest.
        let mut info = self.get_info()?;
        info.manifests.push((manifest.height, manifest_id));
        let info_bytes = info.serialize_p2p();
        batch.put_cf(&cf, INFO_KEY, &info_bytes);

        self.db
            .raw()
            .write(batch)
            .map_err(|e| SnapshotError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Load a manifest by its 32-byte ID.
    pub fn load_manifest(&self, manifest_id: &[u8; 32]) -> Result<Option<Vec<u8>>, SnapshotError> {
        let mut key = vec![PREFIX_MANIFEST];
        key.extend_from_slice(manifest_id);
        self.db
            .raw()
            .get_cf(&self.db.cf_snapshots(), &key)
            .map_err(|e| SnapshotError::Storage(e.to_string()))
    }

    /// Load a chunk by its 32-byte ID.
    pub fn load_chunk(&self, chunk_id: &[u8; 32]) -> Result<Option<Vec<u8>>, SnapshotError> {
        let mut key = vec![PREFIX_CHUNK];
        key.extend_from_slice(chunk_id);
        self.db
            .raw()
            .get_cf(&self.db.cf_snapshots(), &key)
            .map_err(|e| SnapshotError::Storage(e.to_string()))
    }

    /// Get the current `SnapshotsInfo` (all available snapshots).
    pub fn get_info(&self) -> Result<SnapshotsInfo, SnapshotError> {
        match self
            .db
            .raw()
            .get_cf(&self.db.cf_snapshots(), INFO_KEY)
            .map_err(|e| SnapshotError::Storage(e.to_string()))?
        {
            Some(data) => SnapshotsInfo::deserialize_p2p(&data)
                .map_err(|e| SnapshotError::Storage(format!("bad info: {e}"))),
            None => Ok(SnapshotsInfo {
                manifests: Vec::new(),
            }),
        }
    }

    /// Prune old snapshots, keeping only the `keep` most recent by height.
    ///
    /// Removes manifests and their associated chunks from the DB.
    pub fn prune(&self, keep: u32) -> Result<(), SnapshotError> {
        let mut info = self.get_info()?;
        if info.manifests.len() <= keep as usize {
            return Ok(());
        }

        // Sort by height descending so the newest are first.
        info.manifests.sort_by(|a, b| b.0.cmp(&a.0));

        // Split off entries beyond `keep` -- these will be removed.
        let to_remove: Vec<(u32, [u8; 32])> = info.manifests.split_off(keep as usize);

        let cf = self.db.cf_snapshots();
        let mut batch = rocksdb::WriteBatch::default();

        for (_, manifest_id) in &to_remove {
            // Load the manifest to discover its chunk IDs.
            let mut mkey = vec![PREFIX_MANIFEST];
            mkey.extend_from_slice(manifest_id);
            if let Some(manifest_bytes) = self
                .db
                .raw()
                .get_cf(&cf, &mkey)
                .map_err(|e| SnapshotError::Storage(e.to_string()))?
            {
                if let Ok(manifest) = SnapshotManifest::deserialize(&manifest_bytes) {
                    for chunk_id in &manifest.chunk_ids {
                        let mut ckey = vec![PREFIX_CHUNK];
                        ckey.extend_from_slice(chunk_id);
                        batch.delete_cf(&cf, &ckey);
                    }
                }
            }
            batch.delete_cf(&cf, &mkey);
        }

        // Persist the trimmed info.
        let info_bytes = info.serialize_p2p();
        batch.put_cf(&cf, INFO_KEY, &info_bytes);

        self.db
            .raw()
            .write(batch)
            .map_err(|e| SnapshotError::Storage(e.to_string()))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Periodic snapshot creation
// ---------------------------------------------------------------------------

/// Create a snapshot from the persistent UTXO DB if conditions are met.
///
/// Conditions:
/// - `storing_utxo_snapshots > 0`
/// - `height % make_snapshot_every == make_snapshot_every - 1`
/// - Node is near chain tip (`estimated_tip - height <= make_snapshot_every`)
///
/// Returns `true` if a snapshot was created.
pub fn maybe_create_snapshot(
    utxo_db: &ergo_storage::utxo_db::UtxoDb,
    snapshots_db: &SnapshotsDb,
    height: u32,
    make_snapshot_every: u32,
    storing_utxo_snapshots: u32,
    estimated_tip: u32,
) -> Result<bool, SnapshotError> {
    if storing_utxo_snapshots == 0 {
        return Ok(false);
    }
    if make_snapshot_every == 0 || height % make_snapshot_every != make_snapshot_every - 1 {
        return Ok(false);
    }
    if estimated_tip.saturating_sub(height) > make_snapshot_every {
        return Ok(false);
    }

    let metadata = utxo_db
        .metadata()
        .map_err(|e| SnapshotError::Storage(format!("{e}")))?
        .ok_or_else(|| SnapshotError::Storage("no UTXO metadata".into()))?;

    let (manifest, chunks) =
        create_snapshot_chunks(utxo_db.iter_entries(), height, metadata.digest);

    tracing::info!(
        height,
        chunks = chunks.len(),
        entries = manifest.total_entries,
        "creating UTXO snapshot"
    );

    snapshots_db.store_snapshot(&manifest, &chunks)?;
    snapshots_db.prune(storing_utxo_snapshots)?;

    Ok(true)
}

// ---------------------------------------------------------------------------
// Chunk creation / parsing
// ---------------------------------------------------------------------------

/// Create snapshot chunks from an iterator of UTXO entries.
///
/// Each entry is `(key: [u8; 32], value: Vec<u8>)`. Entries are packed into
/// chunks of approximately [`CHUNK_TARGET_BYTES`] each.
///
/// Returns the manifest and a vector of `(chunk_id, chunk_bytes)`.
pub fn create_snapshot_chunks(
    entries: impl Iterator<Item = SnapshotEntry>,
    height: u32,
    digest: [u8; 33],
) -> (SnapshotManifest, Vec<SnapshotEntry>) {
    let mut all_chunks: Vec<SnapshotEntry> = Vec::new();
    let mut total_entries: u64 = 0;

    // Accumulate entries for the current chunk.
    let mut current_entries: Vec<SnapshotEntry> = Vec::new();
    let mut current_size: usize = 4; // leading u32 count

    for (key, value) in entries {
        // Each entry: 32 (key) + 4 (value_len) + value.len()
        let entry_size = 32 + 4 + value.len();

        // If adding this entry would exceed the target and we already have
        // entries, flush the current chunk first.
        if !current_entries.is_empty() && current_size + entry_size > CHUNK_TARGET_BYTES {
            let chunk_bytes = serialize_chunk(&current_entries);
            let chunk_id = blake2b256(&chunk_bytes);
            all_chunks.push((chunk_id, chunk_bytes));
            total_entries += current_entries.len() as u64;

            current_entries.clear();
            current_size = 4;
        }

        current_size += entry_size;
        current_entries.push((key, value));
    }

    // Flush the last chunk (if any entries remain).
    if !current_entries.is_empty() {
        let chunk_bytes = serialize_chunk(&current_entries);
        let chunk_id = blake2b256(&chunk_bytes);
        all_chunks.push((chunk_id, chunk_bytes));
        total_entries += current_entries.len() as u64;
    }

    let chunk_ids: Vec<[u8; 32]> = all_chunks.iter().map(|(id, _)| *id).collect();

    let manifest = SnapshotManifest {
        height,
        digest,
        chunk_ids,
        total_entries,
    };

    (manifest, all_chunks)
}

/// Serialize a list of entries into chunk bytes.
///
/// Format (big-endian):
/// ```text
/// u32 count
/// N * (32 key + u32 value_len + value_bytes)
/// ```
fn serialize_chunk(entries: &[([u8; 32], Vec<u8>)]) -> Vec<u8> {
    let count = entries.len() as u32;
    let total: usize = entries.iter().map(|(_, v)| 32 + 4 + v.len()).sum();
    let mut buf = Vec::with_capacity(4 + total);

    buf.extend_from_slice(&count.to_be_bytes());
    for (key, value) in entries {
        buf.extend_from_slice(key);
        buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buf.extend_from_slice(value);
    }
    buf
}

/// Parse a chunk back into its constituent entries.
pub fn parse_chunk(data: &[u8]) -> Result<Vec<SnapshotEntry>, SnapshotError> {
    if data.len() < 4 {
        return Err(SnapshotError::TruncatedData("chunk too short for count"));
    }

    let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut entries = Vec::with_capacity(count);
    let mut pos = 4;

    for _ in 0..count {
        // Need at least 32 (key) + 4 (value_len)
        if pos + 36 > data.len() {
            return Err(SnapshotError::TruncatedData(
                "chunk truncated at entry key/len",
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let value_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + value_len > data.len() {
            return Err(SnapshotError::TruncatedData(
                "chunk truncated at entry value",
            ));
        }
        let value = data[pos..pos + value_len].to_vec();
        pos += value_len;

        entries.push((key, value));
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod snapshot_db_tests {
    use super::*;

    #[test]
    fn from_shared_snapshots_db() {
        let tmp = tempfile::tempdir().unwrap();
        let node_db = Arc::new(NodeDb::open(tmp.path()).unwrap());
        let _db1 = SnapshotsDb::from_shared(node_db.clone());
        let _db2 = SnapshotsDb::from_shared(node_db.clone());

        // Write a raw key-value via the NodeDb, read it back.
        let cf = node_db.cf_snapshots();
        node_db.raw().put_cf(&cf, b"snap-key", b"snap-val").unwrap();
        let val = node_db.raw().get_cf(&cf, b"snap-key").unwrap();
        assert_eq!(val.as_deref(), Some(b"snap-val".as_slice()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_serialize_deserialize_roundtrip() {
        let manifest = SnapshotManifest {
            height: 500_000,
            digest: [0x42; 33],
            chunk_ids: vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]],
            total_entries: 1_234_567,
        };

        let bytes = manifest.serialize();
        let restored = SnapshotManifest::deserialize(&bytes).unwrap();
        assert_eq!(manifest, restored);
    }

    #[test]
    fn create_and_parse_chunks_roundtrip() {
        // Create 10 entries, chunk them, parse back, verify all entries present.
        let entries: Vec<([u8; 32], Vec<u8>)> = (0u8..10)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = i;
                let value = vec![i; 100];
                (key, value)
            })
            .collect();

        let (manifest, chunks) =
            create_snapshot_chunks(entries.clone().into_iter(), 42, [0x11; 33]);

        assert_eq!(manifest.height, 42);
        assert_eq!(manifest.digest, [0x11; 33]);
        assert_eq!(manifest.total_entries, 10);
        assert_eq!(manifest.chunk_ids.len(), chunks.len());

        // Parse all chunks and gather entries.
        let mut restored: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        for (chunk_id, chunk_bytes) in &chunks {
            assert_eq!(&blake2b256(chunk_bytes), chunk_id);
            let parsed = parse_chunk(chunk_bytes).unwrap();
            restored.extend(parsed);
        }

        assert_eq!(restored.len(), entries.len());
        for (orig, rest) in entries.iter().zip(restored.iter()) {
            assert_eq!(orig.0, rest.0);
            assert_eq!(orig.1, rest.1);
        }
    }

    #[test]
    fn chunk_splitting_with_large_entries() {
        // Create entries totaling >1MB to verify multiple chunks.
        // Each entry: 32 (key) + 4 (len) + 10_000 (value) = 10_036 bytes
        // ~100 entries per chunk. 200 entries should yield >= 2 chunks.
        let entries: Vec<([u8; 32], Vec<u8>)> = (0u16..200)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = (i >> 8) as u8;
                key[1] = (i & 0xFF) as u8;
                let value = vec![(i & 0xFF) as u8; 10_000];
                (key, value)
            })
            .collect();

        let (manifest, chunks) =
            create_snapshot_chunks(entries.clone().into_iter(), 100, [0x22; 33]);

        assert!(
            chunks.len() >= 2,
            "expected at least 2 chunks, got {}",
            chunks.len()
        );
        assert_eq!(manifest.total_entries, 200);
        assert_eq!(manifest.chunk_ids.len(), chunks.len());

        // Verify all entries are recoverable.
        let mut restored: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        for (_id, bytes) in &chunks {
            restored.extend(parse_chunk(bytes).unwrap());
        }
        assert_eq!(restored.len(), 200);
        for (orig, rest) in entries.iter().zip(restored.iter()) {
            assert_eq!(orig.0, rest.0);
            assert_eq!(orig.1, rest.1);
        }
    }

    #[test]
    fn manifest_id_is_deterministic() {
        let manifest = SnapshotManifest {
            height: 12345,
            digest: [0xFF; 33],
            chunk_ids: vec![[0x01; 32]],
            total_entries: 999,
        };

        let id1 = manifest.manifest_id();
        let id2 = manifest.manifest_id();
        assert_eq!(id1, id2);

        // A different manifest should produce a different ID.
        let mut other = manifest.clone();
        other.height = 12346;
        assert_ne!(manifest.manifest_id(), other.manifest_id());
    }

    #[test]
    fn snapshots_info_p2p_roundtrip() {
        let info = SnapshotsInfo {
            manifests: vec![(52223, [0xAA; 32]), (104447, [0xBB; 32])],
        };
        let bytes = info.serialize_p2p();
        let restored = SnapshotsInfo::deserialize_p2p(&bytes).unwrap();
        assert_eq!(restored.manifests.len(), 2);
        assert_eq!(restored, info);
    }

    #[test]
    fn empty_snapshot_produces_no_chunks() {
        let (manifest, chunks) = create_snapshot_chunks(std::iter::empty(), 100, [0; 33]);
        assert_eq!(manifest.total_entries, 0);
        assert!(chunks.is_empty());
        assert!(manifest.chunk_ids.is_empty());
        assert_eq!(manifest.height, 100);
        assert_eq!(manifest.digest, [0; 33]);
    }

    #[test]
    fn parse_chunk_error_on_truncated_data() {
        // Too short for count.
        assert!(parse_chunk(&[0, 0]).is_err());

        // Claims 1 entry but no data follows.
        let bad = [0, 0, 0, 1];
        assert!(parse_chunk(&bad).is_err());
    }

    #[test]
    fn manifest_deserialize_error_on_truncated() {
        assert!(SnapshotManifest::deserialize(&[0; 10]).is_err());

        // Valid header claiming 1 chunk but missing data.
        let mut short = vec![0u8; 41]; // height(4) + digest(33) + chunk_count(4)
        short[40] = 1; // chunk_count = 1
        assert!(SnapshotManifest::deserialize(&short).is_err());
    }

    // -- SnapshotsDb tests --------------------------------------------------

    #[test]
    fn snapshots_db_store_and_load_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let sdb = SnapshotsDb::open(dir.path().join("snapshots")).unwrap();

        let manifest = SnapshotManifest {
            height: 52223,
            digest: [0xAA; 33],
            chunk_ids: vec![[0xBB; 32]],
            total_entries: 100,
        };
        let chunks = vec![([0xBB; 32], vec![0x01, 0x02, 0x03])];

        sdb.store_snapshot(&manifest, &chunks).unwrap();

        let manifest_id = manifest.manifest_id();
        let loaded = sdb.load_manifest(&manifest_id).unwrap();
        assert!(loaded.is_some());
        let restored = SnapshotManifest::deserialize(&loaded.unwrap()).unwrap();
        assert_eq!(restored.height, 52223);
    }

    #[test]
    fn snapshots_db_store_and_load_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let sdb = SnapshotsDb::open(dir.path().join("snapshots")).unwrap();

        let manifest = SnapshotManifest {
            height: 100,
            digest: [0; 33],
            chunk_ids: vec![[0xCC; 32]],
            total_entries: 1,
        };
        let chunk_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let chunks = vec![([0xCC; 32], chunk_data.clone())];

        sdb.store_snapshot(&manifest, &chunks).unwrap();

        let loaded = sdb.load_chunk(&[0xCC; 32]).unwrap();
        assert_eq!(loaded.unwrap(), chunk_data);
    }

    #[test]
    fn snapshots_db_get_info_lists_all() {
        let dir = tempfile::tempdir().unwrap();
        let sdb = SnapshotsDb::open(dir.path().join("snapshots")).unwrap();

        // Empty DB returns empty info.
        let info = sdb.get_info().unwrap();
        assert!(info.manifests.is_empty());

        // Store two snapshots.
        let m1 = SnapshotManifest {
            height: 100,
            digest: [0x01; 33],
            chunk_ids: vec![],
            total_entries: 0,
        };
        let m2 = SnapshotManifest {
            height: 200,
            digest: [0x02; 33],
            chunk_ids: vec![],
            total_entries: 0,
        };
        sdb.store_snapshot(&m1, &[]).unwrap();
        sdb.store_snapshot(&m2, &[]).unwrap();

        let info = sdb.get_info().unwrap();
        assert_eq!(info.manifests.len(), 2);
    }

    #[test]
    fn snapshots_db_prune_removes_old() {
        let dir = tempfile::tempdir().unwrap();
        let sdb = SnapshotsDb::open(dir.path().join("snapshots")).unwrap();

        // Store 3 snapshots at heights 100, 200, 300.
        for h in [100u32, 200, 300] {
            let mut digest = [0u8; 33];
            digest[0] = h as u8;
            let m = SnapshotManifest {
                height: h,
                digest,
                chunk_ids: vec![],
                total_entries: 0,
            };
            sdb.store_snapshot(&m, &[]).unwrap();
        }

        assert_eq!(sdb.get_info().unwrap().manifests.len(), 3);

        // Prune to keep only the most recent 1.
        sdb.prune(1).unwrap();

        let info = sdb.get_info().unwrap();
        assert_eq!(info.manifests.len(), 1);
        assert_eq!(info.manifests[0].0, 300); // highest height kept
    }

    #[test]
    fn snapshots_db_prune_with_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let sdb = SnapshotsDb::open(dir.path().join("snapshots")).unwrap();

        let chunk_id = [0xDD; 32];
        let m = SnapshotManifest {
            height: 100,
            digest: [0; 33],
            chunk_ids: vec![chunk_id],
            total_entries: 1,
        };
        sdb.store_snapshot(&m, &[(chunk_id, vec![0xAA])]).unwrap();

        // Store a newer snapshot.
        let m2 = SnapshotManifest {
            height: 200,
            digest: [0x01; 33],
            chunk_ids: vec![],
            total_entries: 0,
        };
        sdb.store_snapshot(&m2, &[]).unwrap();

        // Prune to keep 1 (should remove height=100 and its chunk).
        sdb.prune(1).unwrap();

        assert!(
            sdb.load_chunk(&chunk_id).unwrap().is_none(),
            "pruned chunk should be gone"
        );
    }

    // -- maybe_create_snapshot tests ----------------------------------------

    #[test]
    fn maybe_create_snapshot_at_correct_height() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_db = ergo_storage::utxo_db::UtxoDb::open(dir.path().join("utxo")).unwrap();
        let sdb = SnapshotsDb::open(dir.path().join("snap")).unwrap();

        // Set up some UTXO data.
        let meta = ergo_storage::utxo_db::UtxoMetadata {
            digest: [0x42; 33],
            version: [0xBB; 32],
        };
        utxo_db
            .apply_changes(&[([0x01; 32], vec![0xAA])], &[], &meta)
            .unwrap();

        // Height 52223 with make_snapshot_every=52224 triggers (52223 % 52224 == 52223).
        let created = maybe_create_snapshot(&utxo_db, &sdb, 52223, 52224, 2, 52223).unwrap();
        assert!(created);

        let info = sdb.get_info().unwrap();
        assert_eq!(info.manifests.len(), 1);
        assert_eq!(info.manifests[0].0, 52223);
    }

    #[test]
    fn maybe_create_snapshot_skips_wrong_height() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_db = ergo_storage::utxo_db::UtxoDb::open(dir.path().join("utxo")).unwrap();
        let sdb = SnapshotsDb::open(dir.path().join("snap")).unwrap();

        let meta = ergo_storage::utxo_db::UtxoMetadata {
            digest: [0; 33],
            version: [0; 32],
        };
        utxo_db.apply_changes(&[], &[], &meta).unwrap();

        // Height 52222 should NOT trigger.
        let created = maybe_create_snapshot(&utxo_db, &sdb, 52222, 52224, 2, 52222).unwrap();
        assert!(!created);
    }

    #[test]
    fn maybe_create_snapshot_skips_when_far_from_tip() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_db = ergo_storage::utxo_db::UtxoDb::open(dir.path().join("utxo")).unwrap();
        let sdb = SnapshotsDb::open(dir.path().join("snap")).unwrap();

        let meta = ergo_storage::utxo_db::UtxoMetadata {
            digest: [0; 33],
            version: [0; 32],
        };
        utxo_db.apply_changes(&[], &[], &meta).unwrap();

        // Height is correct but tip is far away.
        let created = maybe_create_snapshot(&utxo_db, &sdb, 52223, 52224, 2, 200_000).unwrap();
        assert!(!created);
    }

    #[test]
    fn maybe_create_snapshot_disabled_when_storing_zero() {
        let dir = tempfile::tempdir().unwrap();
        let utxo_db = ergo_storage::utxo_db::UtxoDb::open(dir.path().join("utxo")).unwrap();
        let sdb = SnapshotsDb::open(dir.path().join("snap")).unwrap();

        let created = maybe_create_snapshot(&utxo_db, &sdb, 52223, 52224, 0, 52223).unwrap();
        assert!(!created);
    }
}
