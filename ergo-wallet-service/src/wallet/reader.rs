//! Read-only wallet view over the redb tables, with fallible reads
//! for boot rehydration and other wallet consumers.

use crate::wallet::error::WalletStoreError;
use crate::wallet::tables::*;
use crate::wallet::types::{Balance, BoxProvenance, BoxStatus, WalletBox, WalletTransaction};
use crate::wallet::WalletScanCursor;
use redb::{ReadTransaction, ReadableTable, ReadableTableMetadata};

/// A wallet box surfaced through a reserved scan id (9 mining / 10 payments),
/// paired with its full serialized bytes for `ScanBoxEntry.bytes`. `box_bytes`
/// is empty when the box predates the [`WALLET_BOX_BYTES`] table (backfilled by
/// a `/wallet/rescan`).
pub struct ReservedScanBox {
    pub wallet_box: WalletBox,
    pub box_bytes: Vec<u8>,
}

/// A tracked wallet pubkey with the metadata the native `GET /wallet/addresses`
/// surfaces. Ordered by `path_idx` ascending (insertion / derivation order). The
/// address string is rendered by the caller — the bridge knows the network
/// prefix; the reader stays network-agnostic.
pub struct TrackedAddressMeta {
    /// Monotonic tracked-pubkey index (the `WALLET_TRACKED_PUBKEYS` key index).
    pub path_idx: u64,
    /// Compressed secp256k1 public key (33 bytes).
    pub pubkey: [u8; 33],
    /// BIP32 derivation path components (hardened bits set).
    pub derivation_path: Vec<u32>,
    /// Operator-supplied label; empty for auto-derived keys.
    pub label: String,
    /// Height at which this pubkey was first tracked.
    pub added_at_height: u32,
}

/// EIP-3 first-address derivation path with hardened bits set:
/// `m/44'/429'/0'/0/0`. The exact components the wallet persists for the
/// first-address key (see `TrackedPubkeyMeta.derivation_path`); the miner
/// reward-key resolver matches against this and nothing else.
const EIP3_FIRST_ADDRESS_PATH: [u32; 5] = [44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 0];

/// Outcome of resolving the wallet's EIP-3 first-address pubkey for use as
/// the miner reward key. Three states, kept distinct end-to-end
/// (wallet store → mining source → API boundary) so consumers can map them to
/// the right transport:
/// - `Ready` → 200 with the key,
/// - `Pending` → 503 (wallet tracking not initialized yet; retry),
/// - `Corrupt` → 500 (tracking exists but is inconsistent; operator must fix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardKeyResolution {
    /// Exactly one tracked key at the EIP-3 first-address path.
    Ready([u8; 33]),
    /// `WALLET_TRACKED_PUBKEYS` is missing or empty — wallet never unlocked,
    /// no keys derived yet. Transient.
    Pending,
    /// Tracking exists but is wrong: non-empty table with zero or multiple
    /// rows at the exact EIP-3 path, or a decode/read failure. Not transient.
    Corrupt,
}

/// Lifetime'd read view over wallet tables in a single redb read
/// transaction. Created by the service wallet store.
pub struct WalletReader<'tx> {
    txn: &'tx ReadTransaction,
}

pub(crate) fn committed_tip_in(
    txn: &ReadTransaction,
) -> Result<Option<(u32, [u8; 32])>, WalletStoreError> {
    let table = match txn.open_table(CHAIN_STATE_META) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let bytes = match table.get("chain_state")? {
        Some(value) => value.value().to_vec(),
        None => return Ok(None),
    };
    if bytes.len() < 40 + 32 + 4 {
        return Err(WalletStoreError::decode(
            "chain_state row is shorter than the required full-block fields",
        ));
    }
    let score_len = u32::from_be_bytes(bytes[36..40].try_into().unwrap()) as usize;
    let full_id_start = 40usize
        .checked_add(score_len)
        .ok_or_else(|| WalletStoreError::decode("chain_state score length overflows"))?;
    let height_start = full_id_start
        .checked_add(32)
        .ok_or_else(|| WalletStoreError::decode("chain_state full-block id overflows"))?;
    if bytes.len() < height_start + 4 {
        return Err(WalletStoreError::decode(
            "chain_state row is shorter than the required full-block fields",
        ));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes[full_id_start..height_start]);
    let height = u32::from_be_bytes(bytes[height_start..height_start + 4].try_into().unwrap());
    Ok(Some((height, id)))
}

impl<'tx> WalletReader<'tx> {
    pub fn new(txn: &'tx ReadTransaction) -> Self {
        Self { txn }
    }

    /// Total height the wallet has scanned through. None if the
    /// wallet has never been initialized (table is empty).
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn scan_height(&self) -> Result<Option<u32>, redb::Error> {
        Ok(self.scan_cursor()?.map(|cursor| cursor.height))
    }

    #[allow(clippy::result_large_err)]
    pub fn scan_cursor(&self) -> Result<Option<WalletScanCursor>, redb::Error> {
        let height = match self.txn.open_table(WALLET_SCAN_HEIGHT) {
            Ok(table) => table.get(())?.map(|row| row.value()),
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let Some(height) = height else {
            return Ok(None);
        };
        let stored_id = match self.txn.open_table(WALLET_SCAN_HEADER_ID) {
            Ok(table) => table.get(())?.map(|row| row.value()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(error.into()),
        };
        if height == 0 {
            if stored_id.is_some() {
                return Err(redb::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "height-zero wallet cursor has a header identity",
                )));
            }
            return Ok(Some(WalletScanCursor {
                height,
                header_id: None,
            }));
        }
        if let Some(header_id) = stored_id {
            return Ok(Some(WalletScanCursor {
                height,
                header_id: Some(header_id),
            }));
        }
        Err(redb::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "positive-height wallet cursor has no header identity",
        )))
    }

    #[allow(clippy::result_large_err)]
    pub fn chain_index_header(&self, height: u32) -> Result<Option<[u8; 32]>, redb::Error> {
        let table = match self.txn.open_table(crate::wallet::tables::CHAIN_INDEX) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let Some(bytes) = table.get(height as u64)? else {
            return Ok(None);
        };
        if bytes.value().len() != 32 {
            return Err(redb::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chain index header row is not 32 bytes",
            )));
        }
        let mut header_id = [0u8; 32];
        header_id.copy_from_slice(bytes.value());
        Ok(Some(header_id))
    }

    /// All wallet boxes (any status). Returns an owned `Vec<WalletBox>`
    /// because deserialization needs to happen inside the txn.
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn all_boxes(&self) -> Result<Vec<WalletBox>, redb::Error> {
        let tbl = match self.txn.open_table(WALLET_BOXES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut boxes = Vec::with_capacity(tbl.len()? as usize);
        for entry in tbl.iter()? {
            let (_, v) = entry?;
            let wb: WalletBox = bincode::deserialize(v.value().as_slice()).map_err(|e| {
                redb::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("WalletBox deserialize: {e}"),
                ))
            })?;
            boxes.push(wb);
        }
        Ok(boxes)
    }

    /// One wallet box by id, O(1) (direct `WALLET_BOXES.get`). `None` if the id
    /// is not tracked by the wallet. Backs the native `GET /wallet/boxes/{boxId}`
    /// without the O(n) `all_boxes` scan.
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn box_by_id(&self, box_id: &[u8; 32]) -> Result<Option<WalletBox>, redb::Error> {
        let tbl = match self.txn.open_table(WALLET_BOXES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(g) = tbl.get(box_id)? else {
            return Ok(None);
        };
        let wb: WalletBox = bincode::deserialize(g.value().as_slice()).map_err(|e| {
            redb::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("WalletBox deserialize: {e}"),
            ))
        })?;
        Ok(Some(wb))
    }

    /// Filtered: only `Confirmed`-status boxes.
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn unspent_boxes(&self) -> Result<Vec<WalletBox>, redb::Error> {
        Ok(self
            .all_boxes()?
            .into_iter()
            .filter(|b| matches!(b.status, BoxStatus::Confirmed))
            .collect())
    }

    /// Wallet boxes surfaced through a reserved scan id, with their serialized
    /// bytes. `mining = true` selects the Mining scan (id 9 — `MinerReward`
    /// provenance); `false` selects Payments/default (id 10 — `Owned`). `spent`
    /// selects `Spent` boxes; otherwise unspent (`Confirmed` or `Immature`).
    ///
    /// Provenance-partitioned, which is a documented divergence from Scala:
    /// Scala migrates a matured mining box from scan 9 → 10, whereas our
    /// provenance is fixed at creation, so a matured mining box stays under 9
    /// here. Every wallet box still appears under exactly one of 9/10.
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn reserved_scan_boxes(
        &self,
        mining: bool,
        spent: bool,
    ) -> Result<Vec<ReservedScanBox>, redb::Error> {
        let boxes: Vec<WalletBox> = self
            .all_boxes()?
            .into_iter()
            .filter(|b| {
                let provenance_ok = if mining {
                    matches!(b.provenance, BoxProvenance::MinerReward)
                } else {
                    matches!(b.provenance, BoxProvenance::Owned)
                };
                let status_ok = if spent {
                    matches!(b.status, BoxStatus::Spent { .. })
                } else {
                    matches!(b.status, BoxStatus::Confirmed | BoxStatus::Immature { .. })
                };
                provenance_ok && status_ok
            })
            .collect();
        let bytes_tbl = match self.txn.open_table(WALLET_BOX_BYTES) {
            Ok(t) => Some(t),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::with_capacity(boxes.len());
        for wb in boxes {
            let box_bytes = match &bytes_tbl {
                Some(t) => t.get(wb.box_id)?.map(|g| g.value()).unwrap_or_default(),
                None => Vec::new(),
            };
            out.push(ReservedScanBox {
                wallet_box: wb,
                box_bytes,
            });
        }
        Ok(out)
    }

    /// Aggregate balance across all `Confirmed` and `Immature` boxes.
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn balance(&self) -> Result<Balance, redb::Error> {
        let mut bal = Balance::default();
        for wb in self.all_boxes()? {
            match wb.status {
                BoxStatus::Confirmed => {
                    bal.confirmed_nano_ergs = bal.confirmed_nano_ergs.saturating_add(wb.value);
                    for (id, amt) in &wb.assets {
                        let entry = bal.tokens.entry(*id).or_insert(0);
                        *entry = entry.saturating_add(*amt);
                    }
                }
                BoxStatus::Immature { .. } => {
                    bal.immature_nano_ergs = bal.immature_nano_ergs.saturating_add(wb.value);
                }
                BoxStatus::Spent { .. } => {} // Excluded from balance.
            }
        }
        Ok(bal)
    }

    /// Wallet transactions, ordered by `(block_height, tx_id)`.
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn all_transactions(&self) -> Result<Vec<WalletTransaction>, redb::Error> {
        let tbl = match self.txn.open_table(WALLET_TXS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut txs = Vec::with_capacity(tbl.len()? as usize);
        for entry in tbl.iter()? {
            let (_, v) = entry?;
            let wt: WalletTransaction =
                bincode::deserialize(v.value().as_slice()).map_err(|e| {
                    redb::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("WalletTransaction deserialize: {e}"),
                    ))
                })?;
            txs.push(wt);
        }
        Ok(txs)
    }

    /// One transaction by id. None if not found.
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn transaction_by_id(
        &self,
        tx_id: &[u8; 32],
    ) -> Result<Option<WalletTransaction>, redb::Error> {
        Ok(self
            .all_transactions()?
            .into_iter()
            .find(|t| &t.tx_id == tx_id))
    }

    /// Iterate `(derivation_path_index, pubkey, derivation_path_components)`
    /// for every tracked pubkey, in derivation-order ASC.
    ///
    /// Distinct from the chain-apply `HydrationSource::tracked_pubkeys`
    /// (which drops the derivation path for hot-path efficiency); this is
    /// the cold-path surface used by `SecretRegistry::from_master_key`
    /// at unlock time.
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    #[allow(clippy::type_complexity)] // (path_idx, pubkey, path_components) tuple — no alias needed
    pub fn tracked_pubkeys_with_paths(
        &self,
    ) -> Result<Vec<(u64, [u8; 33], Vec<u32>)>, redb::Error> {
        let tbl = match self
            .txn
            .open_table(crate::wallet::tables::WALLET_TRACKED_PUBKEYS)
        {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for entry in tbl.iter()? {
            let (k, v) = entry?;
            let key_bytes: [u8; 41] = k.value();
            let (path_idx, pubkey) = crate::wallet::tables::parse_tracked_pubkey_key(&key_bytes);
            let meta: crate::wallet::types::TrackedPubkeyMeta =
                bincode::deserialize(v.value().as_slice()).map_err(|e| {
                    redb::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("TrackedPubkeyMeta deserialize: {e}"),
                    ))
                })?;
            out.push((path_idx, pubkey, meta.derivation_path));
        }
        Ok(out)
    }

    /// Every tracked pubkey with its full metadata (label, added-at height,
    /// derivation path), ordered by `path_idx` ASC. Backs the native
    /// `GET /wallet/addresses`: the caller renders the address from `pubkey` +
    /// network and paginates the owned Vec (`total` = len, page = slice) — all
    /// from this single read txn. A separate method (not a change to
    /// `tracked_pubkeys_with_paths`, which the unlock path
    /// `SecretRegistry::from_master_key` also calls).
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn tracked_addresses_with_meta(&self) -> Result<Vec<TrackedAddressMeta>, redb::Error> {
        let tbl = match self
            .txn
            .open_table(crate::wallet::tables::WALLET_TRACKED_PUBKEYS)
        {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::with_capacity(tbl.len()? as usize);
        for entry in tbl.iter()? {
            let (k, v) = entry?;
            let key_bytes: [u8; 41] = k.value();
            let (path_idx, pubkey) = crate::wallet::tables::parse_tracked_pubkey_key(&key_bytes);
            let meta: crate::wallet::types::TrackedPubkeyMeta =
                bincode::deserialize(v.value().as_slice()).map_err(|e| {
                    redb::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("TrackedPubkeyMeta deserialize: {e}"),
                    ))
                })?;
            out.push(TrackedAddressMeta {
                path_idx,
                pubkey,
                derivation_path: meta.derivation_path,
                label: meta.derivation_path_label,
                added_at_height: meta.added_at_height,
            });
        }
        Ok(out)
    }

    /// Resolve the wallet's EIP-3 first-address pubkey for use as the miner
    /// reward key, by EXACT derivation-path match (`m/44'/429'/0'/0/0`) — not
    /// by insertion order or visible-address position.
    ///
    /// Outcome rules (persisted evidence only; never consults unlock state):
    /// - table missing or empty → `Pending` (wallet not initialized yet);
    /// - exactly one row at the EIP-3 path → `Ready(pubkey)`;
    /// - any other case (zero rows at the path in a NON-empty table, >1 rows at
    ///   the path, or any redb read / bincode decode failure) → `Corrupt`.
    ///
    /// Only true absence/emptiness maps to `Pending`; every read/decode
    /// failure is `Corrupt`, never `Pending`.
    pub fn resolve_eip3_reward_key(&self) -> RewardKeyResolution {
        let tbl = match self.txn.open_table(WALLET_TRACKED_PUBKEYS) {
            Ok(t) => t,
            // Table never created → tracking uninitialized → Pending.
            Err(redb::TableError::TableDoesNotExist(_)) => return RewardKeyResolution::Pending,
            // Any other open failure is a real storage problem → Corrupt.
            Err(_) => return RewardKeyResolution::Corrupt,
        };

        // Empty table → uninitialized → Pending. A read error on len → Corrupt.
        match tbl.is_empty() {
            Ok(true) => return RewardKeyResolution::Pending,
            Ok(false) => {}
            Err(_) => return RewardKeyResolution::Corrupt,
        }

        // Non-empty: scan for rows whose meta path == the exact EIP-3 path.
        let iter = match tbl.iter() {
            Ok(it) => it,
            Err(_) => return RewardKeyResolution::Corrupt,
        };
        let mut found: Option<[u8; 33]> = None;
        for entry in iter {
            let (k, v) = match entry {
                Ok(kv) => kv,
                Err(_) => return RewardKeyResolution::Corrupt,
            };
            let key_bytes: [u8; 41] = k.value();
            let (_idx, pubkey) = crate::wallet::tables::parse_tracked_pubkey_key(&key_bytes);
            let meta: crate::wallet::types::TrackedPubkeyMeta =
                match bincode::deserialize(v.value().as_slice()) {
                    Ok(m) => m,
                    Err(_) => return RewardKeyResolution::Corrupt,
                };
            if meta.derivation_path == EIP3_FIRST_ADDRESS_PATH {
                if found.is_some() {
                    // Duplicate rows at the exact path — ambiguous, never guess.
                    return RewardKeyResolution::Corrupt;
                }
                found = Some(pubkey);
            }
        }

        match found {
            Some(pk) => RewardKeyResolution::Ready(pk),
            // Non-empty table but no EIP-3 row — inconsistent tracking.
            None => RewardKeyResolution::Corrupt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::tables::tracked_pubkey_key;
    use crate::wallet::types::TrackedPubkeyMeta;
    use redb::Database;

    // ----- helpers -----

    const EIP3_PATH: [u32; 5] = EIP3_FIRST_ADDRESS_PATH;
    const MASTER_PATH: &[u32] = &[]; // master key has an empty path

    fn pk(b: u8) -> [u8; 33] {
        let mut p = [b; 33];
        p[0] = 0x02; // plausible SEC1 prefix (not validated by the resolver)
        p
    }

    fn meta(path: &[u32]) -> Vec<u8> {
        bincode::serialize(&TrackedPubkeyMeta {
            derivation_path: path.to_vec(),
            derivation_path_label: String::new(),
            added_at_height: 0,
        })
        .unwrap()
    }

    /// A seeded tracked-pubkey row: `(path_index, pubkey, derivation_path)`.
    type SeedRow<'a> = (u64, [u8; 33], &'a [u32]);

    /// Build a fresh redb DB, optionally seeding `WALLET_TRACKED_PUBKEYS`
    /// rows. When `rows` is `None`, the table is never created (simulates a
    /// brand-new node).
    fn db_with(rows: Option<&[SeedRow]>) -> (Database, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("s.redb")).unwrap();
        if let Some(rows) = rows {
            let wtxn = db.begin_write().unwrap();
            {
                let mut tbl = wtxn.open_table(WALLET_TRACKED_PUBKEYS).unwrap();
                for (idx, pubkey, path) in rows {
                    tbl.insert(tracked_pubkey_key(*idx, pubkey), meta(path))
                        .unwrap();
                }
            }
            wtxn.commit().unwrap();
        }
        (db, dir)
    }

    fn resolve(db: &Database) -> RewardKeyResolution {
        let rtxn = db.begin_read().unwrap();
        WalletReader::new(&rtxn).resolve_eip3_reward_key()
    }

    // ----- happy path -----

    #[test]
    fn positive_cursor_without_identity_is_not_filled_from_chain_index() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("s.redb")).unwrap();
        let wtxn = db.begin_write().unwrap();
        wtxn.open_table(CHAIN_INDEX)
            .unwrap()
            .insert(7, [4; 32].as_slice())
            .unwrap();
        wtxn.open_table(WALLET_SCAN_HEIGHT)
            .unwrap()
            .insert((), 7)
            .unwrap();
        wtxn.commit().unwrap();
        let rtxn = db.begin_read().unwrap();
        assert!(WalletReader::new(&rtxn).scan_cursor().is_err());
    }

    #[test]
    fn height_zero_cursor_with_identity_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("s.redb")).unwrap();
        let wtxn = db.begin_write().unwrap();
        wtxn.open_table(WALLET_SCAN_HEIGHT)
            .unwrap()
            .insert((), 0)
            .unwrap();
        wtxn.open_table(WALLET_SCAN_HEADER_ID)
            .unwrap()
            .insert((), [4; 32])
            .unwrap();
        wtxn.commit().unwrap();
        let rtxn = db.begin_read().unwrap();
        assert!(WalletReader::new(&rtxn).scan_cursor().is_err());
    }

    #[test]
    fn resolve_eip3_reward_key_exact_path_is_ready() {
        // Master (index 0, empty path) + EIP-3 child (index 1) — the normal
        // post-unlock shape. Resolver must return the CHILD, by exact path.
        let child = pk(0xC1);
        let (db, _d) = db_with(Some(&[(0, pk(0xA0), MASTER_PATH), (1, child, &EIP3_PATH)]));
        assert_eq!(resolve(&db), RewardKeyResolution::Ready(child));
    }

    // ----- error paths -----

    #[test]
    fn resolve_eip3_reward_key_missing_table_is_pending() {
        let (db, _d) = db_with(None);
        assert_eq!(resolve(&db), RewardKeyResolution::Pending);
    }

    #[test]
    fn resolve_eip3_reward_key_empty_table_is_pending() {
        let (db, _d) = db_with(Some(&[]));
        assert_eq!(resolve(&db), RewardKeyResolution::Pending);
    }

    #[test]
    fn resolve_eip3_reward_key_master_only_is_corrupt() {
        // Non-empty table with NO row at the EIP-3 path → inconsistent
        // tracking, not "pending". Master alone must not be used as reward key.
        let (db, _d) = db_with(Some(&[(0, pk(0xA0), MASTER_PATH)]));
        assert_eq!(resolve(&db), RewardKeyResolution::Corrupt);
    }

    #[test]
    fn resolve_eip3_reward_key_duplicate_path_is_corrupt() {
        // Two rows at the exact EIP-3 path — ambiguous, never best-effort pick.
        let (db, _d) = db_with(Some(&[
            (1, pk(0xC1), &EIP3_PATH),
            (2, pk(0xC2), &EIP3_PATH),
        ]));
        assert_eq!(resolve(&db), RewardKeyResolution::Corrupt);
    }
}
