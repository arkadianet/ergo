//! Read-only wallet view over the redb tables. Implements the
//! `HydrationSource` trait for boot rehydration. Read paths used
//! by both internal scan/maturity logic AND the REST `/wallet/*`
//! handlers in `ergo-api`.

use crate::wallet::tables::*;
use crate::wallet::types::{Balance, BoxStatus, WalletBox, WalletTransaction};
use redb::{ReadTransaction, ReadableTable, ReadableTableMetadata};

/// EIP-3 first-address derivation path with hardened bits set:
/// `m/44'/429'/0'/0/0`. The exact components the wallet persists for the
/// first-address key (see `TrackedPubkeyMeta.derivation_path`); the miner
/// reward-key resolver matches against this and nothing else.
const EIP3_FIRST_ADDRESS_PATH: [u32; 5] = [44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 0];

/// Outcome of resolving the wallet's EIP-3 first-address pubkey for use as
/// the miner reward key. Three states, kept distinct end-to-end
/// (ergo-state → ergo-mining → ergo-api) so the API can map them to the
/// right transport:
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
/// transaction. Created via `crate::store::StateStore::wallet_reader()`
/// (Task 38).
pub struct WalletReader<'tx> {
    txn: &'tx ReadTransaction,
}

impl<'tx> WalletReader<'tx> {
    pub fn new(txn: &'tx ReadTransaction) -> Self {
        Self { txn }
    }

    /// Total height the wallet has scanned through. None if the
    /// wallet has never been initialized (table is empty).
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn scan_height(&self) -> Result<Option<u32>, redb::Error> {
        let tbl = match self.txn.open_table(WALLET_SCAN_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(tbl.get(()).ok().flatten().map(|g| g.value()))
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

    /// Filtered: only `Confirmed`-status boxes.
    #[allow(clippy::result_large_err)] // redb::Error shape is fixed upstream
    pub fn unspent_boxes(&self) -> Result<Vec<WalletBox>, redb::Error> {
        Ok(self
            .all_boxes()?
            .into_iter()
            .filter(|b| matches!(b.status, BoxStatus::Confirmed))
            .collect())
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
    /// Per the consensus-review constraint: only true absence/emptiness maps to
    /// `Pending`; every read/decode failure is `Corrupt`, never `Pending`.
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

// Implement HydrationSource so WalletState can hydrate. The trait
// lives in this crate (ergo-state) so the dep direction is
// ergo-wallet → ergo-state (clean, non-cyclic).
impl<'tx> crate::wallet::hydration::HydrationSource for WalletReader<'tx> {
    fn tracked_pubkeys(&self) -> Box<dyn Iterator<Item = (u64, [u8; 33])> + '_> {
        let tbl = match self.txn.open_table(WALLET_TRACKED_PUBKEYS) {
            Ok(t) => t,
            Err(_) => return Box::new(std::iter::empty()),
        };
        // Collect inside the txn (can't return a borrow across the
        // txn boundary). For typical wallet sizes (≤ tens of pubkeys)
        // this is fine; revisit if multi-scan makes it a hot path.
        let mut pairs = Vec::new();
        if let Ok(iter) = tbl.iter() {
            for (k, _) in iter.flatten() {
                let k_bytes: [u8; 41] = k.value();
                pairs.push(parse_tracked_pubkey_key(&k_bytes));
            }
        }
        Box::new(pairs.into_iter())
    }

    fn visible_pubkeys(&self) -> Box<dyn Iterator<Item = (u32, [u8; 33])> + '_> {
        let tbl = match self.txn.open_table(WALLET_VISIBLE_ADDRESSES) {
            Ok(t) => t,
            Err(_) => return Box::new(std::iter::empty()),
        };
        // Collect — redb iteration gives keys in ASC byte order,
        // which for u32 keys = numeric ASC order natively.
        let mut pairs = Vec::new();
        if let Ok(iter) = tbl.iter() {
            for (k, v) in iter.flatten() {
                pairs.push((k.value(), v.value()));
            }
        }
        Box::new(pairs.into_iter())
    }

    fn change_address_pubkey(&self) -> Option<[u8; 33]> {
        let tbl = self.txn.open_table(WALLET_CHANGE_ADDRESS).ok()?;
        tbl.get(()).ok().flatten().map(|g| g.value())
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
